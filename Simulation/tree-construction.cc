#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/timer.h"
#include "ns3/log.h"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/sha.h"
#include <secp256k1.h>
#include <secp256k1_rangeproof.h>

#include <vector>
#include <map>
#include <set>
#include <iostream>
#include <algorithm>
#include <queue>
#include <bitset>
#include <chrono>
#include <thread>

using namespace ns3;
using namespace CryptoPP;

NS_LOG_COMPONENT_DEFINE ("SimpleTreeConstruction");

using namespace CryptoPP;

class RingSigHelper {
public:
    struct RingSignature {
        Integer e_0;
        std::vector<Integer> s;
    };

    static RingSignature Sign(const std::string& msg, 
                              const std::vector<ECDSA<ECP, SHA256>::PublicKey>& ring, 
                              const ECDSA<ECP, SHA256>::PrivateKey& privKey, 
                              int signerIdx) 
    {
        AutoSeededRandomPool prng;
        const DL_GroupParameters_EC<ECP>& params = privKey.GetGroupParameters();
        const ECP& ec = params.GetCurve();
        const ECPPoint& G = params.GetSubgroupGenerator();
        const Integer& n = params.GetSubgroupOrder();
        
        size_t ringSize = ring.size();
        RingSignature sig;
        sig.s.resize(ringSize);

        Integer u(prng, Integer::One(), n - 1);
        std::vector<Integer> e(ringSize);

        ECPPoint R = ec.ScalarMultiply(G, u);
        
        for (size_t i = 1; i < ringSize; ++i) {
            size_t idx = (signerIdx + i) % ringSize;
            
            e[idx] = HashToInteger(msg, R, n);

            sig.s[idx] = Integer(prng, Integer::One(), n - 1);

            ECPPoint sG = ec.ScalarMultiply(G, sig.s[idx]);
            ECPPoint eP = ec.ScalarMultiply(ring[idx].GetPublicElement(), e[idx]);
            R = ec.Add(sG, eP);
        }

        e[signerIdx] = HashToInteger(msg, R, n);
        sig.e_0 = e[0];

        const Integer& x = privKey.GetPrivateExponent();
        // s = u - (x * e) mod n
        Integer xe = a_times_b_mod_c(x, e[signerIdx], n);
        sig.s[signerIdx] = u.Minus(xe) % n;

        return sig;
    }

    static bool Verify(const std::string& msg, 
                       const std::vector<ECDSA<ECP, SHA256>::PublicKey>& ring, 
                       const RingSignature& sig) 
    {
        if (ring.size() != sig.s.size()) return false;

        ECDSA<ECP, SHA256>::PublicKey tempKey = ring[0];
        const DL_GroupParameters_EC<ECP>& params = tempKey.GetGroupParameters();
        const ECP& ec = params.GetCurve();
        const ECPPoint& G = params.GetSubgroupGenerator();
        const Integer& n = params.GetSubgroupOrder();

        Integer e_i = sig.e_0;

        for (size_t i = 0; i < ring.size(); ++i) {
            ECPPoint sG = ec.ScalarMultiply(G, sig.s[i]);
            ECPPoint eP = ec.ScalarMultiply(ring[i].GetPublicElement(), e_i);
            ECPPoint R = ec.Add(sG, eP);

            Integer next_e = HashToInteger(msg, R, n);
            
            if (i == ring.size() - 1) {
                return (next_e == sig.e_0);
            } else {
                e_i = next_e;
            }
        }
        return false;
    }

    static std::vector<uint8_t> Serialize(const RingSignature& sig) {
        std::vector<uint8_t> data;
        
        auto appendInt = [&](const Integer& val) {
            size_t req = val.MinEncodedSize();
            data.push_back((uint8_t)req);
            size_t currentSize = data.size();
            data.resize(currentSize + req);
            val.Encode(&data[currentSize], req);
        };

        appendInt(sig.e_0);
        data.push_back((uint8_t)sig.s.size());
        for(const auto& val : sig.s) {
            appendInt(val);
        }
        return data;
    }
    
    static RingSignature Deserialize(const std::vector<uint8_t>& data) {
        RingSignature sig;
        size_t offset = 0;
        
        auto readInt = [&](Integer& val) {
            if (offset >= data.size()) return;
            size_t len = data[offset++];
            val.Decode(&data[offset], len);
            offset += len;
        };

        readInt(sig.e_0);
        if (offset < data.size()) {
            size_t count = data[offset++];
            for(size_t i=0; i<count; ++i) {
                Integer sVal;
                readInt(sVal);
                sig.s.push_back(sVal);
            }
        }
        return sig;
    }

private:
    static Integer HashToInteger(const std::string& msg, const ECPPoint& R, const Integer& modulus) {
        SHA256 hash;
        hash.Update((const byte*)msg.data(), msg.size());
        
        std::vector<byte> buf(64);
        R.x.Encode(buf.data(), R.x.MinEncodedSize());
        hash.Update(buf.data(), R.x.MinEncodedSize());
        R.y.Encode(buf.data(), R.y.MinEncodedSize());
        hash.Update(buf.data(), R.y.MinEncodedSize());

        byte digest[SHA256::DIGESTSIZE];
        hash.Final(digest);
        
        Integer result(digest, sizeof(digest));
        return result % modulus;
    }
};

const int K = 3;
const int N = 200;
const double trustCoeff = 0.15;
const double TIMEOUT_SEC = 0.2;
const int MOCK_DR_ALG_MS = 5;
const int CHILDREN_DEGREE_LIMIT = 5;
const int PARENTS_DEGREE_LIMIT = 5;
const int chunkSize = 32;
const int minGroupSize = 5;
const secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
double maxTime = 0.0;
int notConstructedNodes = 0;
int seed;

enum MessageType {
  TREE_BUILD_PROPOSAL,
  TREE_BUILD_ACK,
  TREE_BUILD_CONFIRM,
  TREE_BUILD_REJECT,
  UP,
  APPROVE,
  GROUP_COMMIT,
  GROUP_NOT_COMMIT,
  PROPOSE_GROUP,
  GROUP_CONFIRM,
  GROUP_REJECT
};

class TreeHeader : public Header {
public:
  static TypeId GetTypeId () { static TypeId tid = TypeId ("ns3::TreeHeader").SetParent<Header>(); return tid; }
  TypeId GetInstanceTypeId () const override { return GetTypeId (); }
  uint32_t GetSerializedSize () const override { return sizeof(type) + sizeof(treeId) + sizeof(senderId) + sizeof(level) + sizeof(uint32_t) + data.size(); }
  void Serialize (Buffer::Iterator start) const override {
    start.WriteU8(type);
    start.WriteU8(treeId);
    start.WriteU32(senderId);
    start.WriteU32(level);
    start.WriteU32(static_cast<uint32_t>(data.size()));
    if (!data.empty()) {
      start.Write(&data[0], data.size());
    }
  }
  uint32_t Deserialize (Buffer::Iterator start) override {
    type = start.ReadU8();
    treeId = start.ReadU8();
    senderId = start.ReadU32();
    level = start.ReadU32();
    uint32_t dataSize = start.ReadU32();
    data.resize(dataSize);
    if (dataSize > 0) {
      start.Read(&data[0], dataSize);
    }
    return GetSerializedSize();
  }
  void Print (std::ostream &os) const override { os << "Type: " << (int)type << " Tree: " << (int)treeId; }

  uint8_t type;
  uint8_t treeId;
  uint32_t senderId;
  uint32_t level;
  std::vector<uint8_t> data;
};

std::vector<byte> EcdsaSign(const byte* message, size_t msgLen, const ECDSA<ECP, SHA256>::PrivateKey& privKey) {
    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::Signer signer(privKey);
    size_t sigLen = signer.MaxSignatureLength();
    std::vector<byte> signature(sigLen);
    sigLen = signer.SignMessage(prng, message, msgLen, signature.data());
    signature.resize(sigLen);
    return signature;
}

bool EcdsaVerify(const byte* message, size_t msgLen, const std::vector<byte>& signature, const ECDSA<ECP, SHA256>::PublicKey& pubKey) {
    ECDSA<ECP, SHA256>::Verifier verifier(pubKey);
    return verifier.VerifyMessage(message, msgLen, signature.data(), signature.size());
}

std::string GetKeysHash(const std::vector<ECPPoint>& ring, const ECP& curve) {
  SHA256 hash;
  for (const auto& pt : ring) {
    byte buf[33];
    size_t len = curve.EncodedPointSize(true);
    hash.Update(buf, len);
  }
  byte digest[SHA256::DIGESTSIZE];
  hash.Final(digest);
  return std::string((char*)digest, sizeof(digest));
}

Integer H1(const std::string& keysHash, const std::string& message, const ECPPoint& R, const ECP& curve, const Integer& order) {
  SHA256 hash;
  hash.Update((const byte*)keysHash.data(), keysHash.size());
  hash.Update((const byte*)message.data(), message.size());
  byte buf[33];
  size_t len = curve.EncodedPointSize(true);
  hash.Update(buf, len);
  byte digest[SHA256::DIGESTSIZE];
  hash.Final(digest);
  return Integer(digest, sizeof(digest)) % order;
}

class TreeApp : public Application {
public:
  TreeApp () : socket(nullptr), nodeId(0) {}
  virtual ~TreeApp() {}
  static TypeId GetTypeId () { static TypeId tid = TypeId ("TreeApp").SetParent<Application>(); return tid; }

  struct PhaseTimings {
    std::chrono::_V2::system_clock::time_point treeBuildStart;
    std::chrono::_V2::system_clock::time_point treeBuildEnd;
    std::chrono::_V2::system_clock::time_point groupFormationStart;
    std::chrono::_V2::system_clock::time_point groupFormationEnd;
    std::chrono::_V2::system_clock::time_point overallStart;
    std::chrono::_V2::system_clock::time_point overallEnd;
    bool treeBuildComplete;
    
    PhaseTimings() : treeBuildComplete(false) {}
  };
  
  PhaseTimings timings[K];
  
  static std::map<int, std::vector<double>> treeBuildTimes;
  static std::map<int, std::vector<double>> groupFormTimes;
  static std::map<int, std::vector<double>> overallTimes;

  static std::vector<double> individualSignTimesSmall;
  static std::vector<double> individualVerifyTimesSmall;
  static std::vector<double> individualSignTimesMedium;
  static std::vector<double> individualVerifyTimesMedium;
  static std::vector<double> individualSignTimesBig;
  static std::vector<double> individualVerifyTimesBig;
  static std::vector<double> individualSignTimesAll;
  static std::vector<double> individualVerifyTimesAll;
  static std::vector<double> totalSignTimes;
  static std::vector<double> totalVerifyTimes;

  void SetKeys(const ECDSA<ECP, SHA256>::PrivateKey& priv, const std::vector<ECDSA<ECP, SHA256>::PublicKey>& allPubs) {
    privKey = priv;
    pubKey = allPubs[nodeId];
    allPubKeys = allPubs;
    params.Initialize(ASN1::secp256k1());
  }

  void Setup (uint32_t id, Ipv4InterfaceContainer interfaces, const std::set<int>& trustedSet, std::vector<int> allUsers) {
    nodeId = id;
    users = allUsers;
    trustedContacts = trustedSet;
    int mh = 0;
    for (auto contact : trustedContacts) {
      int hd = rand() % 3;
      if (hd > mh) mh = hd;
      hopDist[contact] = hd;
    }

    for (int i = 0; i < N; ++i) {
      contactIps[i] = interfaces.GetAddress(i);
    }

    for (int k = 0; k < K; ++k) {
      pendingChildren[k].clear();

      for (int i = 0; i < mh + 1; ++i) {
        pendingChildren[k].push_back({});
      }
      level[k] = INT_MAX;
      parent[k].clear();
      children[k].clear();
      conUsers.clear();
      chunks[k].clear();
      rejectedMembers[k].clear();
      ownGroup[k].clear();
      confirmedMembers[k].clear();
      for (int i = 0; i < (N + chunkSize - 1) / chunkSize; ++i) {
        std::bitset<chunkSize> bs;
        bs.reset();
        chunks[k].push_back(bs);
      }
      ackCollectionTimer[k] = Timer (Timer::CANCEL_ON_DESTROY);
      confirmRejectTimer[k] = Timer (Timer::CANCEL_ON_DESTROY);
    }

    ownIp = interfaces.GetAddress(nodeId);
  }

  void StartApplication () override {
    TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
    socket = Socket::CreateSocket (GetNode (), tid);
    InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 12345);
    socket->Bind (local);
    socket->SetRecvCallback (MakeCallback (&TreeApp::ReceivePacket, this));

    
    Simulator::Schedule (Seconds (1.0), &TreeApp::StartConstruction, this);
  }

  void StopApplication () override {
    if (socket) socket->Close ();
  }

  Ipv4Address GetContactIp (int id) {
    return contactIps[id];
  }

  void SendPacket (MessageType type, int treeId, int targetId, uint32_t lvl, std::vector<uint8_t> d) {
    std::vector<byte> sig = EcdsaSign(d.data(), d.size(), privKey);

    uint16_t sigLen = sig.size();
    d.insert(d.end(), sig.begin(), sig.end());
    d.insert(d.end(), (byte*)&sigLen, (byte*)&sigLen + 2);

    TreeHeader header;
    header.type = type;
    header.treeId = treeId;
    header.senderId = nodeId;
    header.level = lvl;
    header.data = d;

    Ptr<Packet> p = Create<Packet> ();
    p->AddHeader (header);

    InetSocketAddress remote = InetSocketAddress (GetContactIp(targetId), 12345);
    socket->SendTo (p, 0, remote);
  }

  void ReceivePacket (Ptr<Socket> sock) {
    Ptr<Packet> packet = sock->Recv ();
    TreeHeader header;
    packet->RemoveHeader (header);
    ProcessMessage (header);
  }

  void ProcessMessage (TreeHeader header) {

    int t = header.treeId;
    int sender = header.senderId;
    std::vector<uint8_t> data = header.data;

    if (data.size() < 2) {
      NS_LOG_INFO("Invalid packet: no signature");
      return;
    }
    uint16_t sigLen;
    memcpy(&sigLen, data.data() + data.size() - 2, 2);
    if (data.size() < (size_t)sigLen + 2) {
      NS_LOG_INFO("Invalid signature length, waited " << sigLen);
      return;
    }
    std::vector<byte> sig(data.end() - sigLen - 2, data.end() - 2);
    data.resize(data.size() - sigLen - 2);

    ECDSA<ECP, SHA256>::PublicKey senderPub = allPubKeys[sender];

    if (!EcdsaVerify(data.data(), data.size(), sig, senderPub)) {
      NS_LOG_INFO("Signature verification failed from node " << sender);
      return;
    }
    if (header.type == TREE_BUILD_PROPOSAL) {
      ProcessProposal (t, sender, header.level);
    } else if (header.type == TREE_BUILD_ACK) {
      GetAck (t, sender);
    } else if (header.type == TREE_BUILD_CONFIRM) {
      GetConfirm (t, sender);
    } else if (header.type == TREE_BUILD_REJECT) {
      GetReject (t, sender, 0);
    } else if (header.type == UP) {
      ProcessUp (t, sender, data);
    } else if (header.type == APPROVE) {
      processApprove (t, sender, data);
    } else if (header.type == GROUP_COMMIT) {
      processGroupFormation (t, sender, data);
    } else if (header.type == GROUP_NOT_COMMIT) {
      processGroupNotFormation (t, sender, data);
    } else if (header.type == PROPOSE_GROUP) {
      processGroupProposal (t, sender, data);
    } else if (header.type == GROUP_CONFIRM) {
      processGroupConfirm (t, sender, data);
    } else if (header.type == GROUP_REJECT) {
      processGroupReject (t, sender, data);
    }
  }

  void StartConstruction () {
    constructionStart = Simulator::Now ();
    for (int k = 0; k < K; ++k) {
      timings[k].overallStart = std::chrono::high_resolution_clock::now();
      timings[k].overallEnd = timings[k].overallStart;
      timings[k].treeBuildStart = std::chrono::high_resolution_clock::now();
      Initialization (k);
      if (IsRoot (k)) {
        NS_LOG_INFO("Node " << nodeId << " is root for tree " << k);
        BroadcastProposal (k);
      }
      Simulator::Schedule (Seconds (50.0), &TreeApp::CheckTreeComplete, this, k);
      Simulator::Schedule (Seconds (90.0), &TreeApp::LogAllPhaseMetrics, this, k);
    }
    Simulator::Schedule (Seconds (9.0), &TreeApp::messageSend, this);
  }

  void Initialization (int t) {
    int root = ComputeRoot (t);
    if (nodeId == (uint32_t)root) {
      level[t] = 0;
      parent[t].push_back(nodeId);
    } else {
      level[t] = INT_MAX;
    }
    children[t].clear();
    potentialParents[t] = {};

    int chunk = nodeId / chunkSize;
    int bitPosition = nodeId % chunkSize;
    nonEmptyChunks[t].insert(chunk);
    chunks[t][chunk].set(bitPosition);
  }

  bool IsRoot (int t) {
    return nodeId == (uint32_t)ComputeRoot (t);
  }

  int ComputeRoot (int t) {
    return abs((seed * (t + 1)) % N); // Mock hash
  }

  void BroadcastProposal (int t) {
    if (ackCollectionTimer[t].IsRunning()) {
      return;
    }
    for (auto contact : trustedContacts) {
      if ((conUsers.find(contact) == conUsers.end() || conUsers == trustedContacts) && parent[t].size() < PARENTS_DEGREE_LIMIT) {
        SendPacket (TREE_BUILD_PROPOSAL, t, contact, level[t], {});
      }
    }
    ackCollectionTimer[t].SetFunction (&TreeApp::ProcessPendingChildren, this);
    ackCollectionTimer[t].SetArguments (t);
    ackCollectionTimer[t].Schedule (Seconds (TIMEOUT_SEC*0.5));
  }

  void ProcessProposal (int t, int sender, int l) {
    size_t ps = parent[t].size();
    if (ps >= PARENTS_DEGREE_LIMIT || l + 1 != level[t] && ps > 0) {
      return;
    }
    if (potentialParents[t].count(l+1)){
      potentialParents[t][l + 1].insert(sender);
    }
    else{
      potentialParents[t][l + 1] = {sender};
    }
    
    if (l + 1 <= level[t]) {
      level[t] = l + 1;
      confirmRejectTimer[t].Cancel();
      sentparent[t].insert(sender);
      SendPacket (TREE_BUILD_ACK, t, sender, level[t], {});
      if (confirmRejectTimer[t].IsRunning()) {
        confirmRejectCancelled[t] = true;
        confirmRejectTimer[t].Cancel();
      }
      confirmRejectTimer[t].SetFunction (&TreeApp::HandleConfirmTimeout, this);
      confirmRejectTimer[t].SetArguments (t, sender);
      confirmRejectTimer[t].Schedule (Seconds (TIMEOUT_SEC*0.5));
    }
  }

  void GetAck (int t, int sender) {
    int hd = hopDist[sender];
    pendingChildren[t][hd].insert(sender);
  }

  void ProcessPendingChildren (int t) {
    if (constructed[t]) return;
    int added = 0;
    for (auto pc : pendingChildren[t]) {
      for (auto child : pc){
        if (added < CHILDREN_DEGREE_LIMIT && (conUsers.find(child) == conUsers.end() || conUsers == trustedContacts)) {
        SendPacket (TREE_BUILD_CONFIRM, t, child, level[t], {});
        conUsers.insert(child);
        children[t].push_back(child);
        added++;
      } else {
        SendPacket (TREE_BUILD_REJECT, t, child, level[t], {});
      }
      constructed[t] = true;
      }
    }
    timings[t].groupFormationStart = std::chrono::high_resolution_clock::now();
    timings[t].groupFormationEnd = timings[t].groupFormationStart;
    if (!children[t].empty()){
      double duration = log(N)/log(CHILDREN_DEGREE_LIMIT-2)-level[t]+1;
      if (duration < 0) duration = 1;
      upCollectionTimer[t].SetFunction (&TreeApp::handleUpTimeout, this);
      upCollectionTimer[t].SetArguments (t);
      upCollectionTimer[t].Schedule (Seconds (TIMEOUT_SEC*duration*2.5));
    }
    else
    {
      std::vector<uint8_t> binaryData = PrepareBinaryData(t);
      SendUp(t, binaryData);
    }
  }

  void GetConfirm (int t, int sender) {
    if (sentparent[t].find(sender) == sentparent[t].end()) return;
    sentparent[t].erase(sender);
    potentialParents[t][level[t]].erase(sender);
    if (parent[t].size() >= PARENTS_DEGREE_LIMIT)
    {
      potentialParents[t].clear();
      return;
    }
    parent[t].push_back(sender);
    conUsers.insert(sender);
    if (!parent[t].empty()){
      std::vector<int> toErase;
      int s = potentialParents[t].size();
      for (auto ps : potentialParents[t]) {
        if (ps.first != level[t]) {
            potentialParents[t][ps.first].clear();
        }
      }
    }
    ackCollectionTimer[t].Cancel();
    if (potentialParents[t].empty()){
      if (!timings[t].treeBuildComplete) {
        timings[t].treeBuildEnd = std::chrono::high_resolution_clock::now();
        timings[t].treeBuildComplete = true;
        double duration = (timings[t].treeBuildEnd - timings[t].treeBuildStart).count() / 1e9;
        NS_LOG_INFO("Node " << nodeId << " Tree " << t << 
                    " - Tree Build Phase Complete in " << duration << "s");
      }
      BroadcastProposal(t);
    }
      
  }

  void GetReject (int t, int sender, int type) {
    potentialParents[t][level[t]].erase(sender);
    if (type == 1) {
      potentialParents[t][level[t]].clear();
      sentparent[t].clear();
    }
    else
      sentparent[t].erase(sender);
    if (!parent[t].empty() || !potentialParents[t][level[t]].empty()) return;
    int minLevel = INT_MAX;
    for (int i = 0; i < N; ++i) {
      if (!potentialParents[t][i].empty()) {
        minLevel = i;
        break;
      }
    }
    level[t] = minLevel;
    for (auto p : potentialParents[t][minLevel]) {
      SendPacket (TREE_BUILD_ACK, t, p, level[t], {});
    }
    if (potentialParents[t].empty() && parent[t].empty()) {
      notConstructedNodes++;
    }
  }

  void HandleConfirmTimeout (int t, int sender) {
    if (confirmRejectCancelled[t]) {
      confirmRejectCancelled[t] = false;
      return;
    }
    GetReject (t, sender, 1);
    if (!parent[t].empty()) {
      if (!timings[t].treeBuildComplete) {
        timings[t].treeBuildEnd = std::chrono::high_resolution_clock::now();
        timings[t].treeBuildComplete = true;
        double duration = (timings[t].treeBuildEnd - timings[t].treeBuildStart).count() / 1e9;
        NS_LOG_INFO("Node " << nodeId << " Tree " << t << 
                    " - Tree Build Phase Complete in " << duration << "s");
      }
      BroadcastProposal(t);
    }
  }

  void CheckTreeComplete (int t) {
    if (level[t] == INT_MAX || parent[t].empty()) NS_LOG_INFO ("Node " << nodeId << " Tree " << t << " incomplete" << " Level :" << level[t] << " Parent: " << parent[t].size() << " Children: " << children[t].size());
    else NS_LOG_INFO ("Node " << nodeId << " Tree " << t << " complete. Level :" << level[t] << " Parent: " << parent[t].size() << " Children: " << children[t].size());
  }

  std::vector<uint8_t> PrepareBinaryData(int t){
    std::vector<uint8_t> binaryData;
    binaryData.reserve(chunks[t].size() * 8); 

    uint32_t count = 0;
    for(int k=0; k<4; ++k) binaryData.push_back(0);

    for (auto i : nonEmptyChunks[t]) {
      count++;
      uint32_t idx = static_cast<uint32_t>(i);
      uint32_t val = static_cast<uint32_t>(chunks[t][i].to_ulong());

      binaryData.push_back(idx & 0xFF);
      binaryData.push_back((idx >> 8) & 0xFF);
      binaryData.push_back((idx >> 16) & 0xFF);
      binaryData.push_back((idx >> 24) & 0xFF);

      binaryData.push_back(val & 0xFF);
      binaryData.push_back((val >> 8) & 0xFF);
      binaryData.push_back((val >> 16) & 0xFF);
      binaryData.push_back((val >> 24) & 0xFF);
    }

    binaryData[0] = count & 0xFF;
    binaryData[1] = (count >> 8) & 0xFF;
    binaryData[2] = (count >> 16) & 0xFF;
    binaryData[3] = (count >> 24) & 0xFF;

    return binaryData;
  }

  void SendUp (int t, std::vector<uint8_t> binaryData) {
    for (auto p : parent[t]) {
        if ((uint32_t)p != nodeId) SendPacket (UP, t, p, level[t], binaryData);
    }
  }

  void ProcessUp (int t, int sender, std::vector<uint8_t> binaryData) {
    confirmedChildren[t].insert(sender);

    if (binaryData.size() < 4) return;

    uint32_t count = 0;
    count |= binaryData[0];
    count |= (binaryData[1] << 8);
    count |= (binaryData[2] << 16);
    count |= (binaryData[3] << 24);

    size_t offset = 4;

    for (uint32_t k = 0; k < count; ++k) {
      if (offset + 8 > binaryData.size()) break;

      uint32_t idx = 0;
      idx |= binaryData[offset];
      idx |= (binaryData[offset+1] << 8);
      idx |= (binaryData[offset+2] << 16);
      idx |= (binaryData[offset+3] << 24);
      offset += 4;
      nonEmptyChunks[t].insert(idx);

      uint32_t val = 0;
      val |= binaryData[offset];
      val |= (binaryData[offset+1] << 8);
      val |= (binaryData[offset+2] << 16);
      val |= (binaryData[offset+3] << 24);
      offset += 4;

      std::bitset<chunkSize> bs(val);

      if (idx < chunks[t].size()) {
          chunks[t][idx] |= bs;
      }

      for (size_t bit = 0; bit < chunkSize; ++bit) {
        if (bs[bit]) {
            descendantsCount[t]++;
            ownGroup[t].insert(idx * chunkSize + bit);
            int targetId = idx * chunkSize + bit;
            
            std::vector<uint8_t> bytes(4);
            bytes[0] = targetId & 0xFF;
            bytes[1] = (targetId >> 8) & 0xFF;
            bytes[2] = (targetId >> 16) & 0xFF;
            bytes[3] = (targetId >> 24) & 0xFF;

            SendPacket (APPROVE, t, targetId, level[t], bytes);
        }
      }
    }
  }

  void processApprove (int t, int sender, std::vector<uint8_t> data) {
    approval[t][sender] = data;
  }

  void handleUpTimeout (int t) {
    if (upCollectionCancelled[t]) {
      upCollectionCancelled[t] = false;
      return;
    }
    binaryDataOwnGroup[t] = PrepareBinaryData(t);
    size_t numChunks = chunks[t].size();
    if (IsRoot(t)) {
      NS_LOG_INFO("Node " << nodeId << " is root for tree " << t << ". Final chunks:");
      for (size_t i = 0; i < numChunks; ++i) {
        NS_LOG_INFO("Node " << nodeId << " collected everthing: " << chunks[t][i].to_string());
      }
    }
    else {
      SendUp(t, binaryDataOwnGroup[t]);
    }
    children[t].clear();
    std::copy(confirmedChildren[t].begin(), confirmedChildren[t].end(), std::back_inserter(children[t]));
    confirmedChildren[t].clear();
    
    if (descendantsCount[t] >= minGroupSize) {
      proposeGroup(t, binaryDataOwnGroup[t]);
    }
  }

  void proposeGroup(int t, std::vector<uint8_t> binaryData) {
    for (auto d: ownGroup[t]) {
      if ((uint32_t)d != nodeId)
        SendPacket (PROPOSE_GROUP, t, d, level[t], binaryData);
    }
    double duration = log(N)/log(CHILDREN_DEGREE_LIMIT-2)-level[t]+1;
    if (duration < 0) duration = 1;
    groupConfirmTimer[t].SetFunction (&TreeApp::handleGroupConfirmTimeout, this);
    groupConfirmTimer[t].SetArguments (t);
    groupConfirmTimer[t].Schedule (Seconds (TIMEOUT_SEC*duration));
  }

  void processGroupProposal(int t, int sender, std::vector<uint8_t> binaryData) {
    if (binaryData.size() < 4) return;

    uint32_t count = 0;
    count |= binaryData[0];
    count |= (binaryData[1] << 8);
    count |= (binaryData[2] << 16);
    count |= (binaryData[3] << 24);

    size_t offset = 4;
    int chunk = nodeId / chunkSize;

    for (uint32_t k = 0; k < count; ++k) {
      if (offset + 8 > binaryData.size()) break;

      uint32_t idx = 0;
      idx |= binaryData[offset];
      idx |= (binaryData[offset+1] << 8);
      idx |= (binaryData[offset+2] << 16);
      idx |= (binaryData[offset+3] << 24);
      offset += 4;

      if (idx != chunk) {
        offset += 4;
        continue;
      }

      uint32_t val = 0;
      val |= binaryData[offset];
      val |= (binaryData[offset+1] << 8);
      val |= (binaryData[offset+2] << 16);
      val |= (binaryData[offset+3] << 24);
      offset += 4;

      std::bitset<chunkSize> bs(val);
      if (bs[nodeId % chunkSize]) {
        SendPacket (GROUP_CONFIRM, t, sender, level[t], binaryData);
      }
      else {
        NS_LOG_INFO("Node " << nodeId << " rejecting group proposal for tree " << t << " from node " << sender);
        SendPacket (GROUP_REJECT, t, sender, level[t], binaryData);
      }
    }
  }

  void processGroupConfirm(int t, int sender, std::vector<uint8_t> binaryData) {
    confirmedMembers[t].insert(sender);
  }

  void processGroupReject(int t, int sender, std::vector<uint8_t> binaryData) {
    rejectedMembers[t].insert(sender);
  }

  void handleGroupConfirmTimeout (int t) {
    NS_LOG_INFO("Node " << nodeId << " group formation results for tree " << t << ": Confirmed " << confirmedMembers[t].size() << ", Rejected " << rejectedMembers[t].size() << " own group: " << ownGroup[t].size());
    
    if (!rejectedMembers[t].empty() || confirmedMembers[t].size() != ownGroup[t].size()) {
      for (auto member : ownGroup[t]) {
        if ((uint32_t)member != nodeId)
          SendPacket (GROUP_NOT_COMMIT, t, member, level[t], {});
      }
    }
    else {
      groups[nodeId] = ownGroup[t];
      for (auto member : ownGroup[t]) {
        if ((uint32_t)member != nodeId)
          SendPacket (GROUP_COMMIT, t, member, level[t], binaryDataOwnGroup[t]);
      }
      processGroupFormation(t, nodeId, binaryDataOwnGroup[t]);
    }
  }

  void processGroupFormation(int t, int sender, std::vector<uint8_t> binaryData) {
    size_t numChunks = chunks[t].size();
    
    if (binaryData.size() < numChunks * 4) return;

    std::set<int> groupMembers;
    std::vector<ECDSA<ECP, SHA256>::PublicKey> ring;
    int groupId = 0;

    if (binaryData.size() < 4) return;

    uint32_t count = 0;
    count |= binaryData[0];
    count |= (binaryData[1] << 8);
    count |= (binaryData[2] << 16);
    count |= (binaryData[3] << 24);

    size_t offset = 4;

    for (uint32_t k = 0; k < count; ++k) {
      if (offset + 8 > binaryData.size()) break;

      uint32_t idx = 0;
      idx |= binaryData[offset];
      idx |= (binaryData[offset+1] << 8);
      idx |= (binaryData[offset+2] << 16);
      idx |= (binaryData[offset+3] << 24);
      offset += 4;
      nonEmptyChunks[t].insert(idx);
      uint32_t val = 0;
      val |= binaryData[offset];
      val |= (binaryData[offset+1] << 8);
      val |= (binaryData[offset+2] << 16);
      val |= (binaryData[offset+3] << 24);
      offset += 4;

      std::bitset<chunkSize> bs(val);
      if (idx < chunks[t].size()) {
          chunks[t][idx] |= bs;
      }

      for (size_t bit = 0; bit < chunkSize; ++bit) {
        if (bs[bit]) {
          int id = idx * chunkSize + bit;
          if (id == nodeId) groupId = ring.size();

          groupMembers.insert(id);
          if (id < (int)allPubKeys.size()) {
            ring.push_back(allPubKeys[id]);
          }
        }
      }
    }

    groups[sender] = groupMembers;
    rings[sender] = ring;

    timings[t].groupFormationEnd = std::chrono::high_resolution_clock::now();
    timings[t].overallEnd = std::chrono::high_resolution_clock::now();
  }

  void processGroupNotFormation(int t, int sender, std::vector<uint8_t> data) {
    //NS_LOG_INFO("Node " << nodeId << " received group non-formation for tree " << t << " from node " << sender);
  }

  std::vector<uint8_t> intToBytes(int value) {
    std::vector<uint8_t> bytes(4);
    bytes[0] = static_cast<uint8_t>(value & 0xFF);
    bytes[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    bytes[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    bytes[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    return bytes;
  }

  void LogAllPhaseMetrics(int t) {
    double treeBuildTime = 0.0;
    double groupFormTime = 0.0;
    double overallTime = 0.0;
    
    if (timings[t].treeBuildComplete) {
      treeBuildTime = (timings[t].treeBuildEnd - timings[t].treeBuildStart).count() / 1e9;
      treeBuildTimes[t].push_back(treeBuildTime);
    }
    
    if (timings[t].groupFormationEnd != timings[t].groupFormationStart) {
      groupFormTime = (timings[t].groupFormationEnd - 
                      timings[t].groupFormationStart).count() / 1e9;
      groupFormTimes[t].push_back(groupFormTime);
    }
    
    if (timings[t].overallEnd != timings[t].overallStart) {
      overallTime = (timings[t].overallEnd - timings[t].overallStart).count() / 1e9;
      overallTimes[t].push_back(overallTime);
    }
  }

  static void PrintGlobalStatistics() {
    NS_LOG_INFO("\n========== GLOBAL TIMING STATISTICS ==========");
    
    for (int k = 0; k < K; ++k) {
      NS_LOG_INFO("\n--- Tree " << k << " Statistics ---");
      
      if (!treeBuildTimes[k].empty()) {
        double sum = 0.0, min = 1e9, max = 0.0;
        for (double t : treeBuildTimes[k]) {
          sum += t;
          min = std::min(min, t);
          max = std::max(max, t);
        }
        NS_LOG_INFO("Tree Build Phase:");
        NS_LOG_INFO("  Nodes completed: " << treeBuildTimes[k].size());
        NS_LOG_INFO("  Average time: " << sum / treeBuildTimes[k].size() << "s");
        NS_LOG_INFO("  Min time: " << min << "s");
        NS_LOG_INFO("  Max time: " << max << "s");
      }
      
      if (!groupFormTimes[k].empty()) {
        double sum = 0.0, min = 1e9, max = 0.0;
        for (double t : groupFormTimes[k]) {
          sum += t;
          min = std::min(min, t);
          max = std::max(max, t);
        }
        NS_LOG_INFO("Group Formation Phase:");
        NS_LOG_INFO("  Nodes completed: " << groupFormTimes[k].size());
        NS_LOG_INFO("  Average time: " << sum / groupFormTimes[k].size() << "s");
        NS_LOG_INFO("  Min time: " << min << "s");
        NS_LOG_INFO("  Max time: " << max << "s");
      }
      
      if (!overallTimes[k].empty()) {
        double sum = 0.0, min = 1e9, max = 0.0;
        for (double t : overallTimes[k]) {
          sum += t;
          min = std::min(min, t);
          max = std::max(max, t);
        }
        NS_LOG_INFO("Overall Construction:");
        NS_LOG_INFO("  Nodes completed: " << overallTimes[k].size());
        NS_LOG_INFO("  Average time: " << sum / overallTimes[k].size() << "s");
        NS_LOG_INFO("  Min time: " << min << "s");
        NS_LOG_INFO("  Max time: " << max << "s");
      }
    }
    NS_LOG_INFO("\n==============================================\n");
  }

  void messageSend(){
    auto it = conUsers.begin();
    if (conUsers.empty()) return;
    std::advance(it, rand() % conUsers.size());
    int receiverId = *it;
    int fmax = 0;
    int full = -1;
    int big = -1;
    int medium = -1;
    int small = -1;
    std::string message = "Ring Signature Test Message " + std::to_string(nodeId);
    std::vector<ECDSA<ECP, SHA256>::PublicKey> ringf;
    std::vector<ECDSA<ECP, SHA256>::PublicKey> ringb;
    std::vector<ECDSA<ECP, SHA256>::PublicKey> ringm;
    std::vector<ECDSA<ECP, SHA256>::PublicKey> ringS;
    
    for (auto group : groups){
      int groupSize = group.second.size();
      int step = (N-minGroupSize)/8;
      if (fmax < groupSize && group.second.find(receiverId) != group.second.end()){
        ringf = rings[group.first];
        auto f = std::find(ringf.begin(), ringf.end(), pubKey);
        full = std::distance(ringf.begin(), f);
        fmax = groupSize;
      }
      else if (groupSize >= minGroupSize+step*2.5 && groupSize <= minGroupSize+step*4 && big < 0 && group.second.find(receiverId) != group.second.end()){
        ringb = rings[group.first];
        auto f = std::find(ringb.begin(), ringb.end(), pubKey);
        big = std::distance(ringb.begin(), f);
      }
      else if (groupSize > minGroupSize+step && groupSize <= minGroupSize+step*2.5 && medium < 0 && group.second.find(receiverId) != group.second.end()){
        ringm = rings[group.first];
        auto f = std::find(ringm.begin(), ringm.end(), pubKey);
        medium = std::distance(ringm.begin(), f);
      }
      else if (groupSize >= minGroupSize && groupSize <= minGroupSize+step && small < 0 && group.second.find(receiverId) != group.second.end()){
        ringS = rings[group.first];
        auto f = std::find(ringS.begin(), ringS.end(), pubKey);
        small = std::distance(ringS.begin(), f);
      }
    }
    
    std::map<std::string, RingSigHelper::RingSignature> sigs;

    auto allSignStart = std::chrono::high_resolution_clock::now();

    if (!ringS.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      sigs["small"] = RingSigHelper::Sign(message, ringS, privKey, small);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualSignTimesSmall.push_back(elapsed.count());
    }
    
    if (!ringm.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      sigs["medium"] = RingSigHelper::Sign(message, ringm, privKey, medium);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualSignTimesMedium.push_back(elapsed.count());
    }
    
    if (!ringb.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      sigs["big"] = RingSigHelper::Sign(message, ringb, privKey, big);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualSignTimesBig.push_back(elapsed.count());
    }
    
    if (!ringf.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      sigs["all"] = RingSigHelper::Sign(message, ringf, privKey, full);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualSignTimesAll.push_back(elapsed.count());
    }
    
    auto allSignEnd = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> totalSignElapsed = allSignEnd - allSignStart;
    totalSignTimes.push_back(totalSignElapsed.count());
        
    auto allVerifyStart = std::chrono::high_resolution_clock::now();

    if (!ringS.empty()) {
      auto start = std::chrono::high_resolution_clock::now();
      RingSigHelper::Verify(message, ringS, sigs["small"]);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualVerifyTimesSmall.push_back(elapsed.count());
    }
    
    if (!ringm.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      RingSigHelper::Verify(message, ringm, sigs["medium"]);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualVerifyTimesMedium.push_back(elapsed.count());
    }

    if (!ringb.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      RingSigHelper::Verify(message, ringb, sigs["big"]);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualVerifyTimesBig.push_back(elapsed.count());
    }

    if (!ringf.empty()){
      auto start = std::chrono::high_resolution_clock::now();
      RingSigHelper::Verify(message, ringf, sigs["all"]);
      auto end = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::milli> elapsed = end - start;
      individualVerifyTimesAll.push_back(elapsed.count());
    }

    auto allVerifyEnd = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> totalVerifyElapsed = allVerifyEnd - allVerifyStart;
    totalVerifyTimes.push_back(totalVerifyElapsed.count());
  }

  static void printSignatureStatistics() {
    NS_LOG_INFO("\n========== SIGNATURE TIMING STATISTICS ==========");
    
    auto computeStats = [](const std::vector<double>& times, const std::string& label) {
      if (!times.empty()) {
        double sum = 0.0, min = 1e9, max = 0.0;
        for (double t : times) {
          sum += t;
          min = std::min(min, t);
          max = std::max(max, t);
        }
        NS_LOG_INFO(label << ":");
        NS_LOG_INFO("  Count: " << times.size());
        NS_LOG_INFO("  Average time: " << sum / times.size() << "ms");
        NS_LOG_INFO("  Min time: " << min << "ms");
        NS_LOG_INFO("  Max time: " << max << "ms");
      }
    };

    computeStats(individualSignTimesSmall, "Individual Sign Times (Small)");
    computeStats(individualSignTimesMedium, "Individual Sign Times (Medium)");
    computeStats(individualSignTimesBig, "Individual Sign Times (Big)");
    computeStats(individualSignTimesAll, "Individual Sign Times (All)");
    computeStats(totalSignTimes, "Total Sign Times");

    computeStats(individualVerifyTimesSmall, "Individual Verify Times (Small)");
    computeStats(individualVerifyTimesMedium, "Individual Verify Times (Medium)");
    computeStats(individualVerifyTimesBig, "Individual Verify Times (Big)");
    computeStats(individualVerifyTimesAll, "Individual Verify Times (All)");
    computeStats(totalVerifyTimes, "Total Verify Times");

    NS_LOG_INFO("\n==============================================\n");
  }

protected:
  std::set<int> nonEmptyChunks[K];
  int descendantsCount[K] = {0};
  std::map<int, std::set<int>> groups;
  std::set<int> ownGroup[K];
  std::vector<uint8_t> binaryDataOwnGroup[K];
  std::set<int> rejectedMembers[K];
  std::set<int> confirmedMembers[K];
  Ptr<Socket> socket;
  uint32_t nodeId;
  bool constructed[K] = {false};
  std::vector<int> users;
  std::set<int> trustedContacts;
  std::map<int, int> hopDist;
  std::map<int, Ipv4Address> contactIps;
  Ipv4Address ownIp;
  std::set<int> conUsers;
  int level[K];
  std::vector<int> parent[K];
  std::set<int> sentparent[K];
  std::set<int> confirmedChildren[K];
  std::vector<int> children[K];
  std::vector<std::bitset<chunkSize>> chunks[K];
  std::map<int, std::set<int>> potentialParents[K];
  std::vector<std::set<int>> pendingChildren[K];
  std::map<int, std::vector<uint8_t>> approval[K];
  Timer ackCollectionTimer[K];
  Timer confirmRejectTimer[K];
  bool confirmRejectCancelled[K] = {false};
  Timer upCollectionTimer[K];
  bool upCollectionCancelled[K] = {false};
  Timer groupConfirmTimer[K];
  int pendingUpFromChildren[K];
  ECDSA<ECP, SHA256>::PrivateKey privKey;
  ECDSA<ECP, SHA256>::PublicKey pubKey;
  std::map<int, std::vector<ECDSA<ECP, SHA256>::PublicKey>> rings;
  std::vector<ECDSA<ECP, SHA256>::PublicKey> allPubKeys;
  DL_GroupParameters_EC<ECP> params;
  Time constructionStart;
};

bool IsGraphConnected(const std::vector<std::set<int>>& allTrusted) {
  std::vector<bool> visited(N, false);
  std::queue<int> q;
  q.push(0);
  visited[0] = true;
  int count = 1;

  while (!q.empty()) {
    int u = q.front();
    q.pop();
    for (int v : allTrusted[u]) {
      if (!visited[v]) {
        visited[v] = true;
        q.push(v);
        count++;
      }
    }
  }
  return count == N;
}

std::map<int, std::vector<double>> TreeApp::treeBuildTimes;
std::map<int, std::vector<double>> TreeApp::groupFormTimes;
std::map<int, std::vector<double>> TreeApp::overallTimes;
std::vector<double> TreeApp::individualSignTimesSmall;
std::vector<double> TreeApp::individualVerifyTimesSmall;
std::vector<double> TreeApp::individualSignTimesMedium;
std::vector<double> TreeApp::individualVerifyTimesMedium;
std::vector<double> TreeApp::individualSignTimesBig;
std::vector<double> TreeApp::individualVerifyTimesBig;
std::vector<double> TreeApp::individualSignTimesAll;
std::vector<double> TreeApp::individualVerifyTimesAll;
std::vector<double> TreeApp::totalSignTimes;
std::vector<double> TreeApp::totalVerifyTimes; 

int main (int argc, char *argv[]) {
  srand ( time(NULL) );
  seed = rand();

  std::vector<ECDSA<ECP, SHA256>::PrivateKey> allPriv(N);
  std::vector<ECDSA<ECP, SHA256>::PublicKey> allPub(N);
  AutoSeededRandomPool prng;
  for (int i = 0; i < N; ++i) {
    allPriv[i].Initialize(prng, ASN1::secp256k1());
    allPriv[i].MakePublicKey(allPub[i]);
  }


  NodeContainer nodes;
  nodes.Create (N);

  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", StringValue ("0ns"));
  NetDeviceContainer devices = csma.Install (nodes);

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.0.0.0", "255.255.0.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  std::vector<std::set<int>> allTrusted(N);
  Ptr<UniformRandomVariable> globalRng = CreateObject<UniformRandomVariable> ();
  bool connected = false;
  std::vector<int> users(N);
  for (int i = 0; i < N; ++i) users[i] = i;
  while (!connected) {
    for (int i = 0; i < N; i++) allTrusted[i].clear();
    for (int i = 0; i < N; i++) {
      for (int j = i+1; j < N; j++) {
        if (globalRng->GetValue() <= trustCoeff) {
          allTrusted[i].insert(j);
          allTrusted[j].insert(i);
        }
      }
    }
    connected = IsGraphConnected(allTrusted);
  }

  for (uint32_t i = 0; i < N; ++i) {
    Ptr<TreeApp> app = CreateObject<TreeApp> ();
    app->Setup (i, interfaces, allTrusted[i], users);
    app->SetKeys(allPriv[i], allPub);
    nodes.Get (i)->AddApplication (app);
    app->SetStartTime (Seconds (0.0));
    app->SetStopTime (Seconds (100.0));
  }

  Simulator::Stop (Seconds (100.0));
  Simulator::Run ();

  TreeApp::PrintGlobalStatistics();
  TreeApp::printSignatureStatistics();

  Simulator::Destroy ();
  NS_LOG_INFO ("Simulation finished.");
  return 0;
}