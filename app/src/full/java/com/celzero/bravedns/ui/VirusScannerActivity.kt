package com.celzero.bravedns.ui

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.celzero.bravedns.R
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.MessageDigest
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import by.kirich1409.viewbindingdelegate.viewBinding
import com.celzero.bravedns.adapter.CustomAdapter
import com.celzero.bravedns.viewmodel.ItemsViewModel

class VirusScannerActivity : AppCompatActivity() {

    private lateinit var progressBar: ProgressBar
    private lateinit var totalAppsText: TextView
    private lateinit var threatCountText: TextView
    private lateinit var currentAppText: TextView
    private lateinit var quickScanButton: Button
    private lateinit var deepScanButton: Button

    private var totalAppsCounter = 0
    private var threatCount = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_virus_scanner)

        // Initialize the views
        progressBar = findViewById(R.id.progressBar)
        totalAppsText = findViewById(R.id.total_apps_text)
        threatCountText = findViewById(R.id.threat_count_text)
        currentAppText = findViewById(R.id.current_app_text)
        quickScanButton = findViewById(R.id.quick_scan_button)
        deepScanButton = findViewById(R.id.deep_scan_button)

        // Initialize RecyclerView
        val recyclerview = findViewById<RecyclerView>(R.id.recyclerview)
        recyclerview.layoutManager = LinearLayoutManager(this)
        val data = ArrayList<ItemsViewModel>()
        recyclerview.adapter = CustomAdapter(data)

        // Set button listeners
        quickScanButton.setOnClickListener {
            startScan("test.json", data)
        }

        deepScanButton.setOnClickListener {
            startScan("virus_DB.json", data)
        }
    }

    private fun startScan(jsonFileName: String, recyclerData: ArrayList<ItemsViewModel>) {
        // Disable and hide buttons
        quickScanButton.isEnabled = false
        deepScanButton.isEnabled = false
        quickScanButton.visibility = Button.GONE
        deepScanButton.visibility = Button.GONE

        progressBar.visibility = ProgressBar.VISIBLE
        currentAppText.text = "Starting scan..."

        GlobalScope.launch(Dispatchers.Main) {
            withContext(Dispatchers.IO) {
                scanForThreats(jsonFileName, recyclerData)
            }
            // After scanning, re-enable buttons
            quickScanButton.isEnabled = true
            deepScanButton.isEnabled = true
            quickScanButton.visibility = Button.VISIBLE
            deepScanButton.visibility = Button.VISIBLE
        }
    }

    private fun readVirusDbJson(fileName: String): List<VirusEntry> {
        val virusList = mutableListOf<VirusEntry>()
        try {
            val inputStream = assets.open(fileName)
            val bufferedReader = BufferedReader(InputStreamReader(inputStream))
            val jsonText = bufferedReader.use { it.readText() }

            val jsonObject = JSONObject(jsonText)
            val dataArray: JSONArray = jsonObject.getJSONArray("data")

            for (i in 0 until dataArray.length()) {
                val item = dataArray.getJSONObject(i)
                val hashValue = item.getString("hash")
                val tags = item.getString("tags")
                virusList.add(VirusEntry(hash = hashValue, tags = tags))
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return virusList
    }

    private fun calculateSHA256Hash(filePath: String): String {
        return try {
            val file = File(filePath)
            val digest = MessageDigest.getInstance("SHA-256")
            val inputStream = file.inputStream()

            inputStream.use { stream ->
                val buffer = ByteArray(1024)
                var bytesRead: Int
                while (stream.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }

            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            "Hash calculation error"
        }
    }

    private fun scanForThreats(jsonFileName: String, recyclerData: ArrayList<ItemsViewModel>) {
        val virusDB = readVirusDbJson(jsonFileName)
        val installedPackages = packageManager.getInstalledPackages(PackageManager.GET_META_DATA)

        installedPackages.forEach { packageInfo ->
            val appName = packageInfo.applicationInfo.loadLabel(packageManager).toString()
            val packageHash = calculateSHA256Hash(packageInfo.applicationInfo.sourceDir)

            // Update UI dynamically
            runOnUiThread {
                totalAppsCounter++
                totalAppsText.text = "Total Packages Scanned: $totalAppsCounter"
                currentAppText.text = "Currently Scanning: $appName"
            }

            println("name => " + appName + " | " + packageHash)
            val isThreat = virusDB.any { it.hash.equals(packageHash, ignoreCase = true) }
            if (isThreat) {
                threatCount++
                runOnUiThread {
                    threatCountText.text = "Total Threats Found: $threatCount"
                }
                recyclerData.add(ItemsViewModel(R.drawable.virus_svgrepo_com, appName))
            }
        }

        runOnUiThread {
            progressBar.visibility = ProgressBar.GONE
            currentAppText.text = "Scan Complete"

        }
    }

    data class VirusEntry(val hash: String, val tags: String)
}
