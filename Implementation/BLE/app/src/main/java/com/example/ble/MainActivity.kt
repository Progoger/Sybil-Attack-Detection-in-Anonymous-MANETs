package com.example.ble

import android.Manifest
import android.bluetooth.BluetoothProfile
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.MainScope

class MainActivity : AppCompatActivity(), OnConnectionStateChangeListener {

    private val scope = MainScope()
    private lateinit var centralManager: CentralManager
    private lateinit var peripheralManager: PeripheralManager
    private lateinit var tvStatus: TextView

    private var role: Int = 0

    // Handle permission requests
    private val requestPermissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
        if (permissions.values.all { it }) {
            Toast.makeText(this, "All permissions granted", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "Some permissions were denied", Toast.LENGTH_SHORT).show()
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Request necessary permissions on start
        requestBluetoothPermissions()

        centralManager = CentralManager(scope)
        peripheralManager = PeripheralManager(this)
        peripheralManager.connectionStateListener = this
        tvStatus = findViewById(R.id.tv_status)

        // Set up buttons (assuming you have these in your activity_main.xml)
        findViewById<Button>(R.id.start_central_button).setOnClickListener {
            if (role != 1) {
                Toast.makeText(this, "Starting Central mode...", Toast.LENGTH_SHORT).show()
                centralManager.startScan()
                role = 1
            }
        }

        findViewById<Button>(R.id.start_peripheral_button).setOnClickListener {
            if (role != 2)
            {
                Toast.makeText(this, "Starting Peripheral mode...", Toast.LENGTH_SHORT).show()
                if (ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.BLUETOOTH_CONNECT
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    requestBluetoothPermissions()
                    Log.d("MainActivity", "Permission not granted")
                } else {
                    Log.d("MainActivity", "Permission granted")
                    peripheralManager.startAdvertisingAlone()
                }
                role = 2
            }
        }

        findViewById<Button>(R.id.stop_button).setOnClickListener {
            if (role == 2)
                peripheralManager.stopAdvertising()
            if (role == 1)
                centralManager.disconnectAll()
            role = 0
            Toast.makeText(this, "Stopped all operations.", Toast.LENGTH_SHORT).show()
        }

        findViewById<Button>(R.id.start_peripheral_sybil_button).setOnClickListener {
            if (role != 2)
            {
                Toast.makeText(this, "Starting Peripheral Sybil mode...", Toast.LENGTH_SHORT).show()
                if (ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.BLUETOOTH_CONNECT
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    requestBluetoothPermissions()
                    Log.d("MainActivity", "Permission not granted")
                } else {
                    Log.d("MainActivity", "Permission granted")
                    peripheralManager.startAdvertising()
                }
                role = 2
            }
        }
    }

    private fun requestBluetoothPermissions() {
        val permissionsToRequest = mutableListOf<String>()

        // Add permissions based on Android version
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissionsToRequest.add(Manifest.permission.BLUETOOTH_SCAN)
            permissionsToRequest.add(Manifest.permission.BLUETOOTH_CONNECT)
            permissionsToRequest.add(Manifest.permission.BLUETOOTH_ADVERTISE)
        } else {
            permissionsToRequest.add(Manifest.permission.BLUETOOTH)
            permissionsToRequest.add(Manifest.permission.BLUETOOTH_ADMIN)
            permissionsToRequest.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        val permissionsNotGranted = permissionsToRequest.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (permissionsNotGranted.isNotEmpty()) {
            requestPermissions.launch(permissionsNotGranted.toTypedArray())
        }
    }

    override fun onStateChanged(newState: Int, device: String) {
        runOnUiThread {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    tvStatus.text = "Connected" + device
                    Log.d("MainActivity", "Updated TextView to Connected")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    tvStatus.text = "Disconnected"
                    Log.d("MainActivity", "Updated TextView to Disconnected")
                }
                else -> {
                    tvStatus.text = "Unknown State"
                }
            }
        }
    }
}
