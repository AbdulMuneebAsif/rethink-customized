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

        // Set button listeners
        quickScanButton.setOnClickListener {
            startScan("test.json")
        }

        deepScanButton.setOnClickListener {
            startScan("virus_DB.json")
        }
    }

    private fun startScan(jsonFileName: String) {
        // Disable and hide both buttons during scan
        quickScanButton.isEnabled = false
        deepScanButton.isEnabled = false
        quickScanButton.visibility = Button.GONE
        deepScanButton.visibility = Button.GONE

        // Reset counters
        totalAppsCounter = 0
        threatCount = 0

        // Show progress bar and update UI dynamically
        progressBar.visibility = ProgressBar.VISIBLE
        totalAppsText.text = "Total Packages Scanned: 0"
        threatCountText.text = "Total Threats Found: 0"
        currentAppText.text = "Currently Scanning: None"

        // Run the scanning in a coroutine
        GlobalScope.launch(Dispatchers.Main) {
            withContext(Dispatchers.IO) {
                scanForThreats(jsonFileName)
            }
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

    private fun scanForThreats(jsonFileName: String) {
        val virusDB = readVirusDbJson(jsonFileName)
        val packageManager = packageManager
        val installedPackages: List<PackageInfo> = packageManager.getInstalledPackages(PackageManager.GET_META_DATA)

        installedPackages.forEach { packageInfo ->
            totalAppsCounter++
            runOnUiThread {
                totalAppsText.text = "Total Packages Scanned: $totalAppsCounter"
            }

            val appName = packageInfo.applicationInfo.loadLabel(packageManager).toString()
            val apkFilePath = packageInfo.applicationInfo.sourceDir
            val packageHash = calculateSHA256Hash(apkFilePath)

            runOnUiThread {
                currentAppText.text = "Currently Scanning: $appName"
            }

            virusDB.forEach { virusEntry ->
                if (virusEntry.hash.equals(packageHash, ignoreCase = true)) {
                    threatCount++
                    runOnUiThread {
                        threatCountText.text = "Total Threats Found: $threatCount"
                    }
                    Log.d("VirusScanner", "Threat Detected for $appName!")
                }
            }
        }

        // After the scan completes, re-enable and show the buttons
        runOnUiThread {
            progressBar.visibility = ProgressBar.GONE
            quickScanButton.isEnabled = true
            deepScanButton.isEnabled = true
            quickScanButton.visibility = Button.VISIBLE
            deepScanButton.visibility = Button.VISIBLE
        }
    }

    data class VirusEntry(val hash: String, val tags: String)
}
