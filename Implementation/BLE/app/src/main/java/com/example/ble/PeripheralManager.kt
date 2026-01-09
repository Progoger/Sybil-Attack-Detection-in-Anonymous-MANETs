package com.example.ble
import android.Manifest
import android.bluetooth.*
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import androidx.annotation.RequiresPermission
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope

interface OnConnectionStateChangeListener {
    fun onStateChanged(newState: Int, device: String)
}

class PeripheralManager(private val context: Context) {
    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter = bluetoothManager.adapter
    private val advertiser: BluetoothLeAdvertiser? = bluetoothAdapter.bluetoothLeAdvertiser
    private var gattServer: BluetoothGattServer? = null
    private var connectedDevice: BluetoothDevice? = null
    private val activeAdvertisingSets = mutableMapOf<AdvertisingSet, AdvertisingSetCallback>()
    private val sybilCount = 3
    var connectionStateListener: OnConnectionStateChangeListener? = null

    @RequiresApi(Build.VERSION_CODES.O)
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun startAdvertising() {
        if (advertiser == null || !bluetoothAdapter.isMultipleAdvertisementSupported) {
            Log.e("PeripheralManager", "Device does not support BLE advertising.")
            return
        }

        // 1. Set up the GATT Server
        gattServer = bluetoothManager.openGattServer(context, gattServerCallback)
        val service = BluetoothGattService(GattService.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val characteristic = BluetoothGattCharacteristic(
            GattService.CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        service.addCharacteristic(characteristic)
        gattServer?.addService(service)

        // 2. Set up the advertisement
        for (id in 0 until sybilCount) {
            Log.d("PeripheralManager", "Starting Sybil advertising set $id")
            val params = AdvertisingSetParameters.Builder() // For compatibility; set false for extended ads if Bluetooth 5+
                .setLegacyMode(true)
                .setConnectable(true)
                .setScannable(true)
                .setInterval(AdvertisingSetParameters.INTERVAL_HIGH)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
                .build()
            val advertiseData = AdvertiseData.Builder()
                .addServiceUuid(ParcelUuid(GattService.SERVICE_UUID))
                .addManufacturerData(0xFFFF, "SybilID_$id".toByteArray())  // Custom data to differentiate identities
                .build()
            val scanResponse = AdvertiseData.Builder()
                .setIncludeTxPowerLevel(true)
                .build()

            val advertisingSetCallback = object : AdvertisingSetCallback() {
                override fun onAdvertisingSetStarted(advertisingSet: AdvertisingSet?, txPower: Int, status: Int) {
                    if (status == ADVERTISE_SUCCESS) {
                        Log.d("PeripheralManager", "Sybil identity $id started successfully.")
                        advertisingSet?.let {
                            // Store the set and its callback to be able to stop it later
                            activeAdvertisingSets[it] = this
                        }
                    } else {
                        Log.e("PeripheralManager", "Sybil identity $id failed to start: status $status")
                    }
                }

                override fun onAdvertisingSetStopped(advertisingSet: AdvertisingSet?) {
                    Log.d("PeripheralManager", "Sybil identity $id stopped.")
                }
            }
            advertiser.startAdvertisingSet(params, advertiseData, scanResponse, null, null, advertisingSetCallback)
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun startAdvertisingAlone() {
        if (advertiser == null || !bluetoothAdapter.isMultipleAdvertisementSupported) {
            Log.e("PeripheralManager", "Device does not support BLE advertising.")
            return
        }

        // 1. Set up the GATT Server
        gattServer = bluetoothManager.openGattServer(context, gattServerCallback)
        val service = BluetoothGattService(
            GattService.SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        val characteristic = BluetoothGattCharacteristic(
            GattService.CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        service.addCharacteristic(characteristic)
        gattServer?.addService(service)

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(GattService.SERVICE_UUID))
            .build()

        val advertiseCallback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.d("PeripheralManager", "Advertising started successfully.")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e("PeripheralManager", "Advertising failed with error code: $errorCode")
            }
        }

        // 3. Start advertising
        advertiser?.startAdvertising(settings, data, advertiseCallback)
        Log.d("PeripheralManager", "Id: "+GattService.CHARACTERISTIC_UUID)
        Log.d("PeripheralManager", "Started advertising service.")
    }

    @RequiresApi(Build.VERSION_CODES.O)
    @RequiresPermission(allOf = [Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT])
    fun stopAdvertising() {
        activeAdvertisingSets.forEach { (advertisingSet, callback) ->
            advertiser?.stopAdvertisingSet(callback)
        }
        activeAdvertisingSets.clear()

        gattServer?.close()
        gattServer = null
        Log.d("PeripheralManager", "Stopped all Sybil advertising sets and closed GATT server.")
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.d("PeripheralManager", "Device connected: ${device?.address}")
                connectedDevice = device
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                Log.d("PeripheralManager", "Device disconnected: ${device?.address}")
                connectedDevice = null
            }
            connectedDevice?.let {
                connectionStateListener?.onStateChanged(newState, it.address.toString())
            } ?: connectionStateListener?.onStateChanged(newState, "null")

        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onCharacteristicReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic?) {
            if (characteristic?.uuid == GattService.CHARACTERISTIC_UUID) {
                val message = "Hello from Peripheral!".toByteArray(Charsets.UTF_8)
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, message)
            }
        }
    }
}