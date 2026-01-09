package com.example.ble

import java.util.UUID

object GattService {
    val SERVICE_UUID: UUID = UUID.fromString("0000181d-0000-1000-8000-00805f9b34fb")
    // A unique UUID for our custom characteristic (for sending messages)
    val CHARACTERISTIC_UUID: UUID = UUID.fromString("00002a3d-0000-1000-8000-00805f9b34fb")

}