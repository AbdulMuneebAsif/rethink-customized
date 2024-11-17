package com.celzero.bravedns.ui

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import android.content.Context

class SecurityAdvisorTips {
    val CacheSecurityTips = listOf(

        "Regularly update your software and operating systems to ensure you have the latest security patches, and use strong, unique passwords for each account to minimize the risk of unauthorized access.",
        "Enable two-factor authentication (2FA) whenever possible to add an extra layer of security to your online accounts.",
        "Be cautious of unsolicited emails and avoid clicking on links or downloading attachments from unknown sources.",
        "Regularly back up your important data and files to a secure external location to mitigate the impact of potential cyberattacks.",
        "Use a reputable antivirus and anti-malware software to protect your devices from viruses, ransomware, and other malicious software.",
        "Educate yourself about phishing scams and social engineering techniques to recognize and avoid falling for fraudulent schemes.",
        "Secure your home Wi-Fi network with a strong password and encryption to prevent unauthorized access to your internet connection.",
        "Limit the amount of personal information you share on social media platforms to reduce the risk of identity theft and targeted attacks.",
        "Implement a firewall to control incoming and outgoing network traffic, enhancing your system's defense against cyber threats.",
        "Implement a firewall to control incoming and outgoing network traffic, enhancing your system's defense against cyber threats.",
        "Stay informed about the latest cybersecurity trends and news to understand emerging threats and best practices for protection.",
        "When using public Wi-Fi, connect through a virtual private network (VPN) to encrypt your internet connection and safeguard your data.",
        "Keep an eye out for software vulnerabilities and apply updates promptly to prevent exploitation by cybercriminals.",
        "Secure physical access to your devices by using strong passwords, PINs, or biometric authentication methods.",
        "Implement access controls and user permissions to ensure that only authorized individuals can access sensitive data and systems.",
        "Regularly audit and review your privacy settings on social media and online accounts to maintain control over your personal information.",
        "Be cautious when downloading and installing applications, especially from third-party sources. Stick to official app stores when possible.",
        "Consider using a password manager to generate and store complex passwords securely for all your accounts.",
        "Create a separate email address for online shopping and promotional offers to reduce the exposure of your primary email to potential threats.",
        "Develop a cybersecurity incident response plan to know how to react in case of a breach, minimizing damage and downtime.",
        "Encrypt sensitive data before storing it in the cloud or transmitting it online to prevent unauthorized access to confidential information.",
        "Only download apps from the official Google Play Store to minimize the risk of installing malicious software.",
        "Check and understand the permissions an app requests before granting access to your device's features and data.",
        "Regularly update your Android operating system to ensure you have the latest security patches.",
        "Set up a strong PIN, password, pattern, or biometric lock screen to prevent unauthorized access to your device.",
        "Activate the \"Find My Device\" feature to help locate, lock, or erase your device remotely in case it's lost or stolen.",
        "Be cautious when clicking on links in text messages or answering calls from unknown numbers to avoid phishing scams.",
        "Install a reputable mobile security app to scan for and protect against malware and other threats.",
        "Back up your Android device to a secure location, such as Google Drive, to ensure your important data is safe.",
        "Use strong passwords and WPA3 encryption for your Wi-Fi networks to prevent unauthorized access.",
        "Avoid accessing sensitive information or making transactions over public Wi-Fi networks to minimize the risk of interception.",
        "Don't trust unexpected emails, messages, or pop-ups asking for personal information or urgent action.",
        "Create passwords with a mix of letters, numbers, and symbols. Avoid using easily guessable information like birthdays or names.",
        "Use different passwords for different accounts to prevent a single breach from affecting multiple accounts.",
        "Turn on 2FA whenever possible to add an extra layer of security to your accounts.",
        "Be cautious about sharing personal details on social media or with unknown contacts.",
        "Keep your apps updated to get the latest security patches and features.",
        "Don't click on links or download attachments from unfamiliar sources, even if they seem legitimate.",
        "Change your Wi-Fi password from the default and enable WPA3 encryption for added security.",
        "Set up PINs, passwords, or patterns to lock your devices and prevent unauthorized access.",
        "Look for \"https://\" and a padlock symbol in the address bar before entering sensitive information on websites.",
        "Stay informed about common scams and tactics used by cybercriminals to recognize and avoid them.",
        "Avoid using public computers for sensitive tasks like online banking, as they might be compromised.",
        "Shred paper documents containing personal information before disposing of them.",
        "Be mindful about sharing too much personal information on social media, which can be exploited by attackers.",
        "Use a screen protector and a case to prevent physical damage and access to your device.",
        "Change the default router login credentials and use a strong, unique passphrase for Wi-Fi access.",
        "Regularly back up your data to an external hard drive or a secure cloud service.",
        "Avoid accessing sensitive accounts or making financial transactions on public Wi-Fi networks.",
        "Before providing any information or funds, verify the identity of callers or senders through trusted channels.",
        "If something seems suspicious or too good to be true, it probably is. Trust your gut and proceed with caution.",
        "Keep up with the latest cybersecurity news and trends to stay aware of potential threats and how to protect yourself online."

        )

    // Function to get a random string from the list
    private fun getRandomString(): String {
        val randomIndex = (CacheSecurityTips.indices).random()
        return CacheSecurityTips[randomIndex]
    }


    fun getApiKey(context: Context, keyName: String): String? {
        val assetManager = context.assets
        val inputStream = assetManager.open("Gemini_API_Keys.json")
        val jsonString = inputStream.bufferedReader().use { it.readText() }
        val jsonObject = JSONObject(jsonString)

        return jsonObject.optString(keyName, null) // Returns null if key not found
    }
    // Function to make a POST API call
    fun fetchApiResponse(context:Context, callback: (String) -> Unit) {
        val client = OkHttpClient()


        // Define the JSON payload
        val jsonPayload = """
            {
              "contents": [
                {
                  "parts": [
                    {
                      "text": "Provide a single, unique 2-3 line cybersecurity tip for everyday users based on best practices from NIST, OWASP, CISA, or leading antivirus providers (e.g., Kaspersky, Avast, McAfee). Randomize the topic each time from a wide range, including phishing awareness, software updates, device security, safe browsing habits, and social media privacy. Avoid repeating common topics such as 2FA/MFA. Ensure the tip is distinct and non-repetitive."
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        // Create the request body
        val requestBody = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val key = getApiKey(context, "tips_API_KEY")
        // Build the request
        val request = Request.Builder()
            .url("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key="+key)
            .post(requestBody)
            .addHeader("Content-Type", "application/json")
            .build()

        // Execute the request
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                // In case of failure, return a random string
                callback(getRandomString())
            }

            override fun onResponse(call: Call, response: Response) {
                println("responceBODY => "+ response)
                response.use {
                    if (!response.isSuccessful) {
                        // If response code is not 200, return a random string
                        callback(getRandomString())
                        return
                    }

                    // Parse the response body to extract the "text"
                    val responseBody = response.body?.string() ?: ""

                    val jsonResponse = JSONObject(responseBody)
                    val text = jsonResponse.getJSONArray("candidates")
                        .getJSONObject(0)
                        .getJSONObject("content")
                        .getJSONArray("parts")
                        .getJSONObject(0)
                        .getString("text")

                    // Return the API response text
                    callback(text)
                }
            }
        })
    }
}