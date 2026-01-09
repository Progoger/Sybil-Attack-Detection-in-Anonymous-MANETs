package com.example.ble

import android.os.Build
import com.juul.kable.Scanner
import android.util.Log
import androidx.annotation.RequiresApi
import com.juul.kable.ExperimentalApi
import com.juul.kable.Peripheral
import com.juul.kable.State
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import java.time.Duration
import java.time.Instant
import kotlin.math.abs
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class CentralManager(private val scope: CoroutineScope) {
    private val peripherals = mutableMapOf<String, Peripheral>()
    private val maxConnections = 5
    private var peripheral: Peripheral? = null

    private val rssValues = mutableMapOf<String, Pair<Int, Instant>>()

    private val warningIdentities = mutableMapOf<MutableSet<String>, MutableList<Int>>()

    @RequiresApi(Build.VERSION_CODES.O)
    @OptIn(ExperimentalApi::class)
    fun startScan() {
        scope.launch {
            try {
                val scanner = Scanner {
                    filters {
                        match {
                            services = listOf(GattService.SERVICE_UUID)
                        }
                    }
                }

                Log.d("CentralManager", "Scanning for peripherals...")
                scanner.advertisements
                    .onEach { adv ->
                        val address = adv.address
                        rssValues[address] = Pair(adv.rssi, Instant.now())
                        Log.d("CentralManager/RSSI", "Found peripheral: $address, RSSI: ${adv.rssi}")
                        scope.launch {
                            rssValues.forEach { (address_i, value) ->
                                if (address != address_i) {
                                    val difT = (Duration.between(rssValues[address]!!.second, value.second)).abs()
                                    val difR = abs(rssValues[address]!!.first - value.first)
                                    if (difT.seconds < 3)
                                    {
                                        val key = mutableSetOf(address, address_i)
                                        if (!warningIdentities.containsKey(key))
                                            warningIdentities[key] = mutableListOf(difR)
                                        else
                                            if (warningIdentities[key]!!.size >= 100)
                                            {
                                                warningIdentities[key]!!.removeAt(0)
                                            }
                                            warningIdentities[key]!!.add(difR)
                                    }
                                }
                            }
                        }
                        if (peripherals.size < maxConnections && !peripherals.containsKey(address)) {
                            val peripheral = Peripheral(adv)
                            peripherals[address] = peripheral
                            connectAndMonitor(peripheral, address)
                        }
                    }
                    .launchIn(scope)

                // Optional: Stop scanning after 10s or when max reached
//                delay(10000)  // Scan duration
            } catch (e: Exception) {
                Log.e("CentralManager", "Scan error: ${e.message}")
            }
        }
        scope.launch {
            while (true) {
                delay(5.minutes)
                Log.d("CentralManager/Sybil", "Starting warning check")
                Log.d("CentralManager/Sybil", warningIdentities.size.toString())
                warningIdentities.forEach { address, value ->
                    if (value.average() < 4.15)
                        Log.d(
                            "CentralManager/Sybil",
                            "Warning for $address avg: ${value.average()}, size: ${value.size}"
                        )
                    else
                        Log.d("CentralManager/Sybil", "No warning for $address avg: ${value.average()}, size: ${value.size}")
                }
            }
        }
    }

    private fun connectAndMonitor(peripheral: Peripheral, address: String) {
        scope.launch {
            try {
                peripheral.connect()
                Log.d("CentralManager", "Connected to $address")
                monitorConnectionState(peripheral, address)
            } catch (e: Exception) {
                Log.e("CentralManager", "Connection failed for $address: ${e.message}")
                peripherals.remove(address)
            }
        }
    }

    private fun monitorConnectionState(peripheral: Peripheral, address: String) {
        peripheral.state
            .onEach { state ->
                Log.d("CentralManager", "State for $address: $state")
                if (state is State.Disconnected) {
                    Log.d("CentralManager", "Disconnected from $address")
                    peripherals.remove(address)
                    peripheral.disconnect()// Release resources
                }
            }
            .launchIn(scope)
    }

    fun disconnectAll() {
        scope.launch {
            peripherals.values.forEach { it.disconnect() }
            peripherals.clear()
        }
    }
}
