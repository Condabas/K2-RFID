#include <FS.h>
#include <SPI.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <LittleFS.h>
#include "includes_files/includes.h"

#define SS_PIN 5
#define RST_PIN 21
#define SPK_PIN 15
#define MOSI_PIN 6
#define MISO_PIN 19
#define CLK_PIN 18

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
MFRC522::MIFARE_Key ekey;
WebServer webServer(80);
AES aes;
File upFile;
String upMsg;
MD5Builder md5;

// Creality RFID authentication key
byte creality_key_bytes[6] = {0x71, 0x33, 0x62, 0x75, 0x5e, 0x74};

// Creality AES encryption key: 484043466b526e7a404b4174424a7032
byte creality_aes_key[16] = {0x48, 0x40, 0x43, 0x46, 0x6b, 0x52, 0x6e, 0x7a,
                             0x40, 0x4b, 0x41, 0x74, 0x42, 0x4a, 0x70, 0x32};

IPAddress Server_IP(10, 1, 0, 1);
IPAddress Subnet_Mask(255, 255, 255, 0);
String spoolData = "AB1240276A210100100000FF016500000100000000000000";
String AP_SSID = "K2_RFID";
String AP_PASS = "password";
String WIFI_SSID = "kalvasflam";
String WIFI_PASS = "crys0memor3";
String WIFI_HOSTNAME = "k2.local";
String PRINTER_HOSTNAME = "K2-A11C";
bool encrypted = false;


void setup()
{
  Serial.begin(115200);
  delay(500);
  Serial.println("\n\n=== K2-RFID Starting ===");

  LittleFS.begin(true);
  Serial.println("LittleFS initialized");
  loadConfig();
  Serial.println("Config loaded");

  // Set WiFi credentials (override config file if empty)
  if (WIFI_SSID == "") {
    WIFI_SSID = "kalvasflam";
    WIFI_PASS = "crys0memor3";
    PRINTER_HOSTNAME = "K2-A11C";
  }

  SPI.begin(CLK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
  mfrc522.PCD_Init();
  key = {255, 255, 255, 255, 255, 255};
  pinMode(SPK_PIN, OUTPUT);
  if (AP_SSID == "" || AP_PASS == "")
  {
    AP_SSID = "K2_RFID";
    AP_PASS = "password";
  }
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
  WiFi.softAP(AP_SSID.c_str(), AP_PASS.c_str());
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
  Serial.print("AP Started - SSID: ");
  Serial.println(AP_SSID);
  Serial.println("IP: 10.1.0.1");

  if (WIFI_SSID != "" && WIFI_PASS != "")
  {
    Serial.print("Connecting to WiFi: ");
    Serial.println(WIFI_SSID);
    WiFi.setAutoReconnect(true);
    WiFi.hostname(WIFI_HOSTNAME);
    WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());

    int timeout = 0;
    while (WiFi.status() != WL_CONNECTED && timeout < 20) {
      delay(500);
      Serial.print(".");
      timeout++;
    }

    if (WiFi.status() == WL_CONNECTED)
    {
      IPAddress LAN_IP = WiFi.localIP();
      Serial.println("\nWiFi Connected!");
      Serial.print("IP Address: ");
      Serial.println(LAN_IP);
    }
    else
    {
      Serial.println("\nWiFi Connection Failed!");
    }
  }
  else
  {
    Serial.println("No WiFi credentials - using AP only");
  }
  if (WIFI_HOSTNAME != "")
  {
    String mdnsHost = WIFI_HOSTNAME;
    mdnsHost.replace(".local", "");
    MDNS.begin(mdnsHost.c_str());
  }

  webServer.on("/config", HTTP_GET, handleConfig);
  webServer.on("/index.html", HTTP_GET, handleIndex);
  webServer.on("/", HTTP_GET, handleIndex);
  webServer.on("/material_database.json", HTTP_GET, handleDb);
  webServer.on("/config", HTTP_POST, handleConfigP);
  webServer.on("/spooldata", HTTP_POST, handleSpoolData);
  webServer.on("/spool", HTTP_GET, handleSpoolUI);
  webServer.on("/spool", HTTP_POST, handleSpoolUpdate);

  // Handle AJAX scan requests
  webServer.on("/spoolscan", HTTP_GET, handleSpoolScan);
  webServer.on("/spoolread", HTTP_GET, handleSpoolRead);
  webServer.on("/spoolreset", HTTP_GET, handleSpoolReset);
  webServer.on("/update.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000);
    ESP.restart();
  }, []() {
    handleFwUpdate();
  });
  webServer.on("/updatedb.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000);
    ESP.restart();
  }, []() {
    handleDbUpdate();
  });
  webServer.onNotFound(handle404);
  webServer.begin();

  Serial.println("SPI initialized");
  Serial.println("RC522 initialized");
  Serial.println("Web Server started on port 80");
  Serial.println("=== K2-RFID Ready ===\n");
}


void loop()
{
  webServer.handleClient();
  if (!mfrc522.PICC_IsNewCardPresent())
    return;

  if (!mfrc522.PICC_ReadCardSerial())
    return;

  // Print RFID tag UID
  Serial.print("\nRFID Tag Scanned - UID: ");
  printUID();

  encrypted = false;

  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K)
  {
    tone(SPK_PIN, 400, 400);
    delay(2000);
    return;
  }

  createKey();

  MFRC522::StatusCode status;
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK)
  {
    if (!mfrc522.PICC_IsNewCardPresent())
      return;
    if (!mfrc522.PICC_ReadCardSerial())
      return;
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
      tone(SPK_PIN, 400, 150);
      delay(300);
      tone(SPK_PIN, 400, 150);
      delay(2000);
      return;
    }
    encrypted = true;
  }

  byte blockData[17];
  byte encData[16];
  int blockID = 4;
  for (int i = 0; i < spoolData.length(); i += 16)
  {
    spoolData.substring(i, i + 16).getBytes(blockData, 17);
    if (blockID >= 4 && blockID < 7)
    {
      aes.encrypt(1, blockData, encData);
      mfrc522.MIFARE_Write(blockID, encData, 16);
    }
    blockID++;
  }

  if (!encrypted)
  {
    byte buffer[18];
    byte byteCount = sizeof(buffer);
    byte block = 7;
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    int y = 0;
    for (int i = 10; i < 16; i++)
    {
      buffer[i] = ekey.keyByte[y];
      y++;
    }
    for (int i = 0; i < 6; i++)
    {
      buffer[i] = ekey.keyByte[i];
    }
    mfrc522.MIFARE_Write(7, buffer, 16);
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  tone(SPK_PIN, 1000, 200);
  delay(2000);
}

void printUID()
{
  String uid = "";
  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    if (mfrc522.uid.uidByte[i] < 0x10)
    {
      Serial.print("0");
      uid += "0";
    }
    Serial.print(mfrc522.uid.uidByte[i], HEX);
    uid += String(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();

  // Look up spool in mapping
  lookupSpool(uid);
}

void lookupSpool(String uid)
{
  uid.toUpperCase();
  File mappingFile = LittleFS.open("/spool_mapping.json", "r");

  if (!mappingFile) {
    Serial.println("ERROR: spool_mapping.json not found!");
    return;
  }

  String jsonString = "";
  while (mappingFile.available()) {
    jsonString += (char)mappingFile.read();
  }
  mappingFile.close();

  if (jsonString.indexOf(uid) != -1) {
    Serial.println("Spool Found!");
    // Extract material_id and print
    int materialStart = jsonString.indexOf("\"material_id\":\"") + 15;
    int materialEnd = jsonString.indexOf("\"", materialStart);
    String materialId = jsonString.substring(materialStart, materialEnd);
    Serial.print("Material ID: ");
    Serial.println(materialId);

    int nameStart = jsonString.indexOf("\"material_name\":\"", materialStart) + 17;
    int nameEnd = jsonString.indexOf("\"", nameStart);
    String materialName = jsonString.substring(nameStart, nameEnd);
    Serial.print("Material: ");
    Serial.println(materialName);

    int colorStart = jsonString.indexOf("\"color\":\"", nameStart) + 9;
    int colorEnd = jsonString.indexOf("\"", colorStart);
    String color = jsonString.substring(colorStart, colorEnd);
    Serial.print("Color: ");
    Serial.println(color);
  }
  else {
    Serial.println("Tag not found in spool mapping!");
  }
}

void createKey()
{
  int x = 0;
  byte uid[16];
  byte bufOut[16];
  for (int i = 0; i < 16; i++)
  {
    if (x >= 4)
      x = 0;
    uid[i] = mfrc522.uid.uidByte[x];
    x++;
  }
  aes.encrypt(0, uid, bufOut);
  for (int i = 0; i < 6; i++)
  {
    ekey.keyByte[i] = bufOut[i];
  }
}

void handleIndex()
{
  webServer.send_P(200, "text/html", indexData);
}

void handle404()
{
  webServer.send(404, "text/plain", "Not Found");
}

void handleConfig()
{
  String htmStr = AP_SSID + "|-|" + WIFI_SSID + "|-|" + WIFI_HOSTNAME + "|-|" + PRINTER_HOSTNAME;
  webServer.setContentLength(htmStr.length());
  webServer.send(200, "text/plain", htmStr);
}

void handleConfigP()
{
  if (webServer.hasArg("ap_ssid") && webServer.hasArg("ap_pass") && webServer.hasArg("wifi_ssid") && webServer.hasArg("wifi_pass") && webServer.hasArg("wifi_host") && webServer.hasArg("printer_host"))
  {
    AP_SSID = webServer.arg("ap_ssid");
    if (!webServer.arg("ap_pass").equals("********"))
    {
      AP_PASS = webServer.arg("ap_pass");
    }
    WIFI_SSID = webServer.arg("wifi_ssid");
    if (!webServer.arg("wifi_pass").equals("********"))
    {
      WIFI_PASS = webServer.arg("wifi_pass");
    }
    WIFI_HOSTNAME = webServer.arg("wifi_host");
    PRINTER_HOSTNAME = webServer.arg("printer_host");
    File file = LittleFS.open("/config.ini", "w");
    if (file)
    {
      file.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
    delay(1000);
    ESP.restart();
  }
  else
  {
    webServer.send(417, "text/plain", "Expectation Failed");
  }
}

void handleDb()
{
  File dataFile = LittleFS.open("/matdb.gz", "r");
  if (!dataFile) {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send_P(200, "application/json", material_database, sizeof(material_database));
  }
  else
  {
    webServer.streamFile(dataFile, "application/json");
    dataFile.close();
  }
}

void handleDbUpdate()
{
  upMsg = "";
  if (webServer.uri() != "/updatedb.html") {
    upMsg = "Error";
    return;
  }
  HTTPUpload &upload = webServer.upload();
  if (upload.filename != "material_database.json") {
    upMsg = "Invalid database file<br><br>" + upload.filename;
    return;
  }
  if (upload.status == UPLOAD_FILE_START) {
    if (LittleFS.exists("/matdb.gz")) {
      LittleFS.remove("/matdb.gz");
    }
    upFile = LittleFS.open("/matdb.gz", "w");
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) {
      upFile.write(upload.buf, upload.currentSize);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) {
      upFile.close();
      upMsg = "Database update complete, Rebooting";
    }
  }
}

void handleFwUpdate()
{
  upMsg = "";
  if (webServer.uri() != "/update.html") {
    upMsg = "Error";
    return;
  }
  HTTPUpload &upload = webServer.upload();
  if (!upload.filename.endsWith(".bin")) {
    upMsg = "Invalid update file<br><br>" + upload.filename;
    return;
  }
  if (upload.status == UPLOAD_FILE_START) {
    if (LittleFS.exists("/update.bin")) {
      LittleFS.remove("/update.bin");
    }
    upFile = LittleFS.open("/update.bin", "w");
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) {
      upFile.write(upload.buf, upload.currentSize);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) {
      upFile.close();
    }
    updateFw();
  }
}

void updateFw()
{
  if (LittleFS.exists("/update.bin")) {
    File updateFile;
    updateFile = LittleFS.open("/update.bin", "r");
    if (updateFile) {
      size_t updateSize = updateFile.size();
      if (updateSize > 0) {
        md5.begin();
        md5.addStream(updateFile, updateSize);
        md5.calculate();
        String md5Hash = md5.toString();
        updateFile.close();
        updateFile = LittleFS.open("/update.bin", "r");
        if (updateFile) {
          uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
          if (!Update.begin(maxSketchSpace, U_FLASH)) {
            updateFile.close();
            upMsg = "Update failed<br><br>" + errorMsg(Update.getError());
            return;
          }
          int md5BufSize = md5Hash.length() + 1;
          char md5Buf[md5BufSize];
          md5Hash.toCharArray(md5Buf, md5BufSize) ;
          Update.setMD5(md5Buf);
          long bsent = 0;
          int cprog = 0;
          while (updateFile.available()) {
            uint8_t ibuffer[1];
            updateFile.read((uint8_t *)ibuffer, 1);
            Update.write(ibuffer, sizeof(ibuffer));
            bsent++;
            int progr = ((double)bsent /  updateSize) * 100;
            if (progr >= cprog) {
              cprog = progr + 10;
            }
          }
          updateFile.close();
          LittleFS.remove("/update.bin");
          if (Update.end(true))
          {
            String uHash = md5Hash.substring(0, 10);
            String iHash = Update.md5String().substring(0, 10);
            iHash.toUpperCase();
            uHash.toUpperCase();
            upMsg = "Uploaded:&nbsp; " + uHash + "<br>Installed: " + iHash + "<br><br>Update complete, Rebooting";
          }
          else
          {
            upMsg = "Update failed";
          }
        }
      }
      else {
        updateFile.close();
        LittleFS.remove("/update.bin");
        upMsg = "Error, file is invalid";
        return;
      }
    }
  }
  else
  {
    upMsg = "No update file found";
  }
}

void handleSpoolData()
{
  if (webServer.hasArg("materialColor") && webServer.hasArg("materialType") && webServer.hasArg("materialWeight"))
  {
    String materialColor = webServer.arg("materialColor");
    materialColor.replace("#", "");
    String filamentId = webServer.arg("materialType"); // DB IDs already include the "1" type prefix
    String vendorId = "0276"; // 0276 creality
    String color = "0" + materialColor;
    String filamentLen = GetMaterialLength(webServer.arg("materialWeight"));
    String serialNum = String(random(100000, 999999)); // 000001
    String reserve = "000000";
    spoolData = "AB124" + vendorId + "A2" + filamentId + color + filamentLen + serialNum + reserve + "00000000";
    File file = LittleFS.open("/spool.ini", "w");
    if (file)
    {
      file.print(spoolData);
      file.close();
    }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
  }
  else
  {
    webServer.send(417, "text/plain", "Expectation Failed");
  }
}

String GetMaterialLength(String materialWeight)
{
  if (materialWeight == "1 KG")
  {
    return "0330";
  }
  else if (materialWeight == "750 G")
  {
    return "0247";
  }
  else if (materialWeight == "600 G")
  {
    return "0198";
  }
  else if (materialWeight == "500 G")
  {
    return "0165";
  }
  else if (materialWeight == "250 G")
  {
    return "0082";
  }
  return "0330";
}

String errorMsg(int errnum)
{
  if (errnum == UPDATE_ERROR_OK) {
    return "No Error";
  } else if (errnum == UPDATE_ERROR_WRITE) {
    return "Flash Write Failed";
  } else if (errnum == UPDATE_ERROR_ERASE) {
    return "Flash Erase Failed";
  } else if (errnum == UPDATE_ERROR_READ) {
    return "Flash Read Failed";
  } else if (errnum == UPDATE_ERROR_SPACE) {
    return "Not Enough Space";
  } else if (errnum == UPDATE_ERROR_SIZE) {
    return "Bad Size Given";
  } else if (errnum == UPDATE_ERROR_STREAM) {
    return "Stream Read Timeout";
  } else if (errnum == UPDATE_ERROR_MD5) {
    return "MD5 Check Failed";
  } else if (errnum == UPDATE_ERROR_MAGIC_BYTE) {
    return "Magic byte is wrong, not 0xE9";
  } else {
    return "UNKNOWN";
  }
}

void loadConfig()
{
  if (LittleFS.exists("/config.ini"))
  {
    File file = LittleFS.open("/config.ini", "r");
    if (file)
    {
      String iniData;
      while (file.available())
      {
        char chnk = file.read();
        iniData += chnk;
      }
      file.close();
      if (instr(iniData, "AP_SSID="))
      {
        AP_SSID = split(iniData, "AP_SSID=", "\r\n");
        AP_SSID.trim();
      }

      if (instr(iniData, "AP_PASS="))
      {
        AP_PASS = split(iniData, "AP_PASS=", "\r\n");
        AP_PASS.trim();
      }

      if (instr(iniData, "WIFI_SSID="))
      {
        WIFI_SSID = split(iniData, "WIFI_SSID=", "\r\n");
        WIFI_SSID.trim();
      }

      if (instr(iniData, "WIFI_PASS="))
      {
        WIFI_PASS = split(iniData, "WIFI_PASS=", "\r\n");
        WIFI_PASS.trim();
      }

      if (instr(iniData, "WIFI_HOST="))
      {
        WIFI_HOSTNAME = split(iniData, "WIFI_HOST=", "\r\n");
        WIFI_HOSTNAME.trim();
      }

      if (instr(iniData, "PRINTER_HOST="))
      {
        PRINTER_HOSTNAME = split(iniData, "PRINTER_HOST=", "\r\n");
        PRINTER_HOSTNAME.trim();
      }
      
    }
  }
  else
  {
    File file = LittleFS.open("/config.ini", "w");
    if (file)
    {
      file.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
  }

  if (LittleFS.exists("/spool.ini"))
  {
    File file = LittleFS.open("/spool.ini", "r");
    if (file)
    {
      String iniData;
      while (file.available())
      {
        char chnk = file.read();
        iniData += chnk;
      }
      file.close();
      spoolData = iniData;
    }
  }
  else
  {
    File file = LittleFS.open("/spool.ini", "w");
    if (file)
    {
      file.print(spoolData);
      file.close();
    }
  }
}

String split(String str, String from, String to)
{
  String tmpstr = str;
  tmpstr.toLowerCase();
  from.toLowerCase();
  to.toLowerCase();
  int pos1 = tmpstr.indexOf(from);
  int pos2 = tmpstr.indexOf(to, pos1 + from.length());
  String retval = str.substring(pos1 + from.length(), pos2);
  return retval;
}

bool instr(String str, String search)
{
  int result = str.indexOf(search);
  if (result == -1)
  {
    return false;
  }
  return true;
}

void handleSpoolRead()
{
  Serial.println("\nReading RFID tag data...");
  unsigned long startTime = millis();

  while (millis() - startTime < 10000) {
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String uid = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (mfrc522.uid.uidByte[i] < 0x10) uid += "0";
        uid += String(mfrc522.uid.uidByte[i], HEX);
      }
      uid.toUpperCase();

      Serial.println("Tag UID: " + uid);

      // Try different keys
      MFRC522::MIFARE_Key creality_key_obj;
      for (int i = 0; i < 6; i++) {
        creality_key_obj.keyByte[i] = creality_key_bytes[i];
      }

      // Check card type
      MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
      Serial.print("Card type: ");
      Serial.println(mfrc522.PICC_GetTypeName(piccType));

      String result = "{\"uid\":\"" + uid + "\",\"cardType\":\"" + String(mfrc522.PICC_GetTypeName(piccType)) + "\",\"blocks\":{";
      MFRC522::StatusCode status = MFRC522::STATUS_TIMEOUT;
      bool authenticated = false;

      // Try Creality key (authenticate on block 7, the sector trailer)
      Serial.println("Trying Creality key...");
      status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &creality_key_obj, &(mfrc522.uid));

      Serial.print("  Creality key result: ");
      Serial.println(mfrc522.GetStatusCodeName(status));

      if (status == MFRC522::STATUS_OK) {
        authenticated = true;
        Serial.println("✓ Creality key authenticated!");
      } else {
        // Reset and retry with default key
        Serial.println("  Resetting PCD...");
        mfrc522.PCD_StopCrypto1();
        delay(100);

        // Re-read card after reset
        if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
          Serial.println("Trying default key...");
          delay(50);

          status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
            MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &(mfrc522.uid));

          Serial.print("  Auth result: ");
          Serial.println(mfrc522.GetStatusCodeName(status));

          if (status == MFRC522::STATUS_OK) {
            authenticated = true;
            Serial.println("✓ Default key authenticated!");
          }
        } else {
          Serial.println("  Could not re-read card after reset");
        }
      }

      // If still not authenticated, try generated key (used when writing)
      if (!authenticated) {
        Serial.println("  Resetting for generated key...");
        mfrc522.PCD_StopCrypto1();
        delay(100);

        if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
          Serial.println("Trying generated key...");
          createKey();
          delay(50);

          status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
            MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));

          Serial.print("  Auth result: ");
          Serial.println(mfrc522.GetStatusCodeName(status));

          if (status == MFRC522::STATUS_OK) {
            authenticated = true;
            Serial.println("✓ Generated key authenticated!");
          }
        }
      }

      if (authenticated) {
        Serial.println("Authenticated - reading and decrypting blocks...");

        // Read blocks 4-7
        byte blockData[16];
        byte decData[16];

        for (byte block = 4; block < 8; block++) {
          byte buffer[18];
          byte size = sizeof(buffer);

          status = mfrc522.MIFARE_Read(block, buffer, &size);
          if (status == MFRC522::STATUS_OK) {
            // Copy encrypted data
            for (int i = 0; i < 16; i++) {
              blockData[i] = buffer[i];
            }

            // Try to decrypt with AES
            aes.encrypt(1, blockData, decData);

            String blockHex = "";
            String decHex = "";
            for (byte i = 0; i < 16; i++) {
              if (buffer[i] < 0x10) blockHex += "0";
              blockHex += String(buffer[i], HEX);
              if (decData[i] < 0x10) decHex += "0";
              decHex += String(decData[i], HEX);
            }

            result += "\"" + String(block) + "\":{";
            result += "\"encrypted\":\"" + blockHex + "\",";
            result += "\"decrypted\":\"" + decHex + "\"";
            result += "}";
            if (block < 7) result += ",";

            Serial.println("Block " + String(block) + ":");
            Serial.println("  Encrypted: " + blockHex);
            Serial.println("  Decrypted: " + decHex);
          }
        }
      } else {
        result += "\"error\":\"Authentication failed - could not authenticate with any key\"";
        Serial.println("Could not authenticate with any key");
      }

      result += "}}";
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();

      webServer.send(200, "application/json", result);
      return;
    }
    delay(100);
  }

  webServer.send(408, "application/json", "{\"error\":\"Timeout - no tag detected\"}");
}

void handleSpoolScan()
{
  Serial.println("\nWaiting for tag scan...");
  unsigned long startTime = millis();

  // Wait up to 10 seconds for a tag
  while (millis() - startTime < 10000) {
    webServer.handleClient();

    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String uid = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (mfrc522.uid.uidByte[i] < 0x10) uid += "0";
        uid += String(mfrc522.uid.uidByte[i], HEX);
      }
      uid.toUpperCase();

      Serial.println("Tag scanned: " + uid);
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();

      String response = "{\"success\":true,\"uid\":\"" + uid + "\"}";
      webServer.send(200, "application/json", response);
      return;
    }
    delay(100);
  }

  webServer.send(408, "application/json", "{\"success\":false,\"message\":\"Timeout - no tag detected\"}");
}

void handleSpoolUI()
{
  String html = R"(
<!DOCTYPE html>
<html>
<head>
  <title>K2 RFID Spool Config</title>
  <style>
    body { font-family: arial; background-color: #E0E0E0; padding: 20px; }
    .container { background: white; padding: 20px; border-radius: 10px; max-width: 500px; margin: 0 auto; }
    h1 { color: #0047AB; margin-bottom: 4px; }
    .subtitle { color: #666; margin-top: 0; margin-bottom: 20px; }
    label { display: block; margin-top: 15px; font-weight: bold; }
    input, select { width: 100%; padding: 10px; margin-top: 5px; font-size: 16px; box-sizing: border-box; }
    #writeBtn { background-color: #4CAF50; color: white; padding: 14px; margin-top: 24px; border: none; border-radius: 5px; font-size: 18px; cursor: pointer; width: 100%; }
    #writeBtn:hover { background-color: #388E3C; }
    #writeBtn:disabled { background-color: #ccc; cursor: not-allowed; }
    #resetBtn { background-color: #e53935; color: white; padding: 10px; margin-top: 10px; border: none; border-radius: 5px; font-size: 15px; cursor: pointer; width: 100%; }
    #resetBtn:hover { background-color: #b71c1c; }
    #resetBtn:disabled { background-color: #ccc; cursor: not-allowed; }
    .status { margin-top: 16px; padding: 12px; border-radius: 5px; font-size: 15px; }
    .success { background-color: #4CAF50; color: white; }
    .error { background-color: #f44336; color: white; }
    .waiting { background-color: #e3f2fd; color: #1976d2; }
  </style>
</head>
<body>
  <div class="container">
    <h1>K2 RFID Spool Config</h1>
    <p class="subtitle">Set type &amp; color, then hold tag to writer</p>

    <label>Material Type:</label>
    <select id="material">
      <option value="">Select Material</option>
      <optgroup label="Generic">
        <option value="000001">Generic PLA</option>
        <option value="000002">Generic PLA-Silk</option>
        <option value="000003">Generic PETG</option>
        <option value="000004">Generic ABS</option>
        <option value="000005">Generic TPU</option>
        <option value="000006">Generic PLA-CF</option>
        <option value="000007">Generic ASA</option>
      </optgroup>
      <optgroup label="Creality">
        <option value="101001">Hyper PLA</option>
        <option value="102001">Hyper PLA-CF</option>
        <option value="106002">Hyper PETG</option>
        <option value="103001">Hyper ABS</option>
        <option value="104001">CR-PLA</option>
        <option value="105001">CR-Silk</option>
        <option value="106001">CR-PETG</option>
        <option value="107001">CR-ABS</option>
        <option value="110001">HP-TPU</option>
        <option value="111001">CR-Nylon</option>
        <option value="113001">CR-PLA Carbon</option>
        <option value="114001">CR-PLA Matte</option>
        <option value="116001">CR-TPU</option>
      </optgroup>
    </select>

    <label>Spool Color:</label>
    <input type="color" id="colorPicker" value="#FF0000" style="height: 50px;">

    <button id="writeBtn" type="button">Write to Tag</button>
    <button id="resetBtn" type="button">Reset Tag to Blank</button>

    <div id="status" class="status" style="display:none;"></div>
  </div>

  <script>
    const writeBtn = document.getElementById('writeBtn');
    const resetBtn = document.getElementById('resetBtn');
    const statusDiv = document.getElementById('status');

    function setWorking(working) {
      writeBtn.disabled = working;
      resetBtn.disabled = working;
    }

    function showStatus(msg, type) {
      statusDiv.textContent = msg;
      statusDiv.className = 'status ' + type;
      statusDiv.style.display = 'block';
    }

    writeBtn.addEventListener('click', function() {
      const material = document.getElementById('material').value;
      if (!material) { showStatus('Please select a material type.', 'error'); return; }
      const color = document.getElementById('colorPicker').value;
      setWorking(true);
      writeBtn.textContent = 'Hold tag near reader...';
      showStatus('Waiting for tag — hold it near the reader...', 'waiting');

      fetch('/spool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ material, color })
      })
      .then(r => r.json())
      .then(result => {
        if (result.success) {
          showStatus('Written to tag ' + (result.uid || ''), 'success');
        } else {
          showStatus('Failed: ' + result.message, 'error');
        }
      })
      .catch(err => showStatus('Error: ' + err, 'error'))
      .finally(() => { setWorking(false); writeBtn.textContent = 'Write to Tag'; });
    });

    resetBtn.addEventListener('click', function() {
      if (!confirm('Reset this tag to blank? This will erase all spool data.')) return;
      setWorking(true);
      resetBtn.textContent = 'Hold tag near reader...';
      showStatus('Waiting for tag to reset — hold it near the reader...', 'waiting');

      fetch('/spoolreset')
      .then(r => r.json())
      .then(result => {
        if (result.success) {
          showStatus('Tag ' + (result.uid || '') + ' reset to blank', 'success');
        } else {
          showStatus('Reset failed: ' + result.message, 'error');
        }
      })
      .catch(err => showStatus('Error: ' + err, 'error'))
      .finally(() => { setWorking(false); resetBtn.textContent = 'Reset Tag to Blank'; });
    });
  </script>
</body>
</html>
  )";
  webServer.send(200, "text/html", html);
}

void handleSpoolUpdate()
{
  if(webServer.hasArg("plain")) {
    String json = webServer.arg("plain");
    String material = extractValue(json, "material");
    String color = extractValue(json, "color");

    Serial.println("\n=== Waiting for tag to write ===");
    Serial.println("Material: " + material);
    Serial.println("Color: " + color);

    // Build spool data string (matching Creality/Windows app format)
    // Generic materials (filamentId starts with "0") use vendor 0000; Creality uses 0276.
    String vendorId = (material.length() > 0 && material.charAt(0) == '0') ? "0000" : "0276";
    String batch = "A2";
    String filamentId = material;  // DB IDs (e.g. "101001") already include the "1" type prefix
    String colorWithPrefix = "0" + color.substring(1);  // "#RRGGBB" → "0RRGGBB" (7 chars)
    String filamentLen = "0330";
    String serialNum = "000001";
    String reserve = "00000000000000";
    String printerType = "K2";

    String spoolData = "AB124" + vendorId + batch + filamentId + colorWithPrefix + filamentLen + serialNum + reserve + printerType;
    while (spoolData.length() < 96) spoolData += " ";

    Serial.println("Data: [" + spoolData + "]");
    Serial.println("Length: " + String(spoolData.length()));

    // Scan for any tag within 15 seconds and write to it
    unsigned long startTime = millis();
    while (millis() - startTime < 15000) {
      webServer.handleClient();
      if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
        String tagUid = "";
        for (byte i = 0; i < mfrc522.uid.size; i++) {
          if (mfrc522.uid.uidByte[i] < 0x10) tagUid += "0";
          tagUid += String(mfrc522.uid.uidByte[i], HEX);
        }
        tagUid.toUpperCase();
        Serial.println("Tag detected: " + tagUid);

        if (writeSpoolDataToChip(spoolData)) {
          Serial.println("Success - UID: " + tagUid);
          tone(SPK_PIN, 1000, 150); delay(200);
          tone(SPK_PIN, 1000, 150); delay(200);
          tone(SPK_PIN, 1000, 150); delay(200);
          noTone(SPK_PIN);
          webServer.send(200, "application/json", "{\"success\":true,\"message\":\"Tag written\",\"uid\":\"" + tagUid + "\"}");
        } else {
          Serial.println("Write failed");
          tone(SPK_PIN, 400, 500); delay(600); noTone(SPK_PIN);
          webServer.send(200, "application/json", "{\"success\":false,\"message\":\"Write failed\"}");
        }
        return;
      }
      delay(50);
    }

    Serial.println("Timeout - no tag detected");
    webServer.send(408, "application/json", "{\"success\":false,\"message\":\"Timeout - no tag detected\"}");
  } else {
    webServer.send(400, "application/json", "{\"success\":false,\"message\":\"Invalid request\"}");
  }
}

bool writeSpoolDataToChip(String spoolData)
{
  Serial.println("\n=== Writing Tag (Sector 1 + Sector 2) ===");
  Serial.println("Data: [" + spoolData + "]");
  Serial.println("Length: " + String(spoolData.length()));

  // Convert string to bytes
  byte fullDataBytes[96];
  for (int i = 0; i < 96; i++) {
    fullDataBytes[i] = (i < (int)spoolData.length()) ? (byte)spoolData.charAt(i) : (byte)' ';
  }

  // Always start clean: halt the card, power cycle so it resets to IDLE, re-read.
  // This avoids auth failures caused by residual card state from the scan in handleSpoolUpdate.
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  mfrc522.PCD_AntennaOff();
  delay(100);
  mfrc522.PCD_AntennaOn();
  delay(100);

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    Serial.println("Could not re-read card after initial power cycle");
    return false;
  }

  // Generate ekey from the freshly read UID
  createKey();

  MFRC522::StatusCode status;

  // ===== SECTOR 1 (Blocks 4-6) - ENCRYPTED =====
  // Try ekey first (previously-written tags), fall back to default key (fresh tags).
  Serial.println("\n--- Sector 1: Authenticating ---");
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.println("Ekey failed, trying default key...");
    mfrc522.PCD_StopCrypto1();
    delay(50);
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
      Serial.println("Could not re-read card");
      return false;
    }
    createKey();
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Both keys failed: " + String(mfrc522.GetStatusCodeName(status)));
      mfrc522.PCD_StopCrypto1();
      return false;
    }
    Serial.println("Authenticated with default key");
  } else {
    Serial.println("Authenticated with ekey");
  }

  // Fix block 7 FIRST with explicit known-good access bits (FF 07 80 69).
  // This repairs any access bit corruption left by old buggy writes before we attempt
  // to write the data blocks. We skip reading block 7 — write the full 16 bytes directly.
  Serial.println("Fixing block 7 access bits...");
  {
    byte trailer7[16];
    for (int i = 0; i < 6; i++)      trailer7[i]      = ekey.keyByte[i]; // Key A
    trailer7[6] = 0xFF; trailer7[7] = 0x07; trailer7[8] = 0x80; trailer7[9] = 0x69; // access bits
    for (int i = 0; i < 6; i++)      trailer7[10 + i] = ekey.keyByte[i]; // Key B
    status = mfrc522.MIFARE_Write(7, trailer7, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Block 7 fix failed: " + String(mfrc522.GetStatusCodeName(status)));
    } else {
      Serial.println("Block 7 fixed");
    }
  }

  // Power cycle so the new access bits take effect before writing data blocks.
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  mfrc522.PCD_AntennaOff();
  delay(100);
  mfrc522.PCD_AntennaOn();
  delay(100);

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    Serial.println("Could not re-read card after block 7 fix");
    return false;
  }
  createKey();

  // Re-authenticate sector 1 with the (now corrected) access bits in effect.
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.println("Re-auth after block 7 fix failed: " + String(mfrc522.GetStatusCodeName(status)));
    mfrc522.PCD_StopCrypto1();
    return false;
  }
  Serial.println("Re-authenticated after block 7 fix");

  // Encrypt and write blocks 4, 5, 6
  Serial.println("Writing blocks 4-6 (encrypted)...");
  for (int i = 0; i < 3; i++) {
    byte plain[16], encrypted[16];
    memcpy(plain, &fullDataBytes[i * 16], 16);
    aes.encrypt(1, plain, encrypted);
    status = mfrc522.MIFARE_Write(4 + i, encrypted, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Block " + String(4 + i) + " write failed: " + String(mfrc522.GetStatusCodeName(status)));
      mfrc522.PCD_StopCrypto1();
      return false;
    }
    Serial.println("Block " + String(4 + i) + " written");
  }

  // ===== SECTOR 2 (Blocks 8-10) - PLAIN TEXT =====
  // Card is in "Active" state after the sector 1 write. It won't respond to REQA while
  // active, so we halt it, power-cycle the antenna to reset it to IDLE, then re-read.
  Serial.println("\n--- Sector 2: Authenticating ---");
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  // Brief RF power cycle: card loses power → resets to IDLE state → responds to REQA again
  mfrc522.PCD_AntennaOff();
  delay(100);
  mfrc522.PCD_AntennaOn();
  delay(100);

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    Serial.println("Could not re-read card after power cycle");
    return false;
  }
  Serial.println("Card re-read OK");

  // Authenticate sector 2 (trailer = block 11, still has default key)
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 11, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.println("Sector 2 auth failed: " + String(mfrc522.GetStatusCodeName(status)));
    mfrc522.PCD_StopCrypto1();
    return false;
  }
  Serial.println("Sector 2 authenticated");

  // Write blocks 8, 9, 10 (plain text)
  Serial.println("Writing blocks 8-10 (plain text)...");
  for (int i = 0; i < 3; i++) {
    status = mfrc522.MIFARE_Write(8 + i, &fullDataBytes[48 + i * 16], 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Block " + String(8 + i) + " write failed: " + String(mfrc522.GetStatusCodeName(status)));
      mfrc522.PCD_StopCrypto1();
      return false;
    }
    Serial.println("Block " + String(8 + i) + " written");
  }

  Serial.println("\n=== Tag Written Successfully ===");
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  return true;
}

bool updatePrinterSpoolMapping(String rfidUid, String box, String slot, String material, String color)
{
  // Check if printer is reachable
  if(WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return false;
  }

  // For now, log the mapping that should be added
  Serial.println("RFID Tag: " + rfidUid);
  Serial.println("Box: " + box);
  Serial.println("Slot: " + slot);
  Serial.println("Material ID: " + material);
  Serial.println("Color: " + color);

  // TODO: Implement Moonraker API call to update printer file
  // This requires downloading, parsing, modifying, and re-uploading the JSON file
  // For now, return false to indicate manual step needed

  return false;
}

bool resetTag()
{
  Serial.println("\n=== Resetting Tag ===");

  // Start clean: power cycle so card resets to IDLE state, then re-read.
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  mfrc522.PCD_AntennaOff();
  delay(100);
  mfrc522.PCD_AntennaOn();
  delay(100);

  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    Serial.println("Could not re-read card after initial power cycle");
    return false;
  }

  createKey();

  MFRC522::StatusCode status;
  byte emptyBlock[16] = {0};

  // === SECTOR 1 (Blocks 4-6): authenticate with ekey or default ===
  Serial.println("Authenticating sector 1...");
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.println("Ekey failed, trying default...");
    mfrc522.PCD_StopCrypto1();
    delay(100);
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
      Serial.println("Could not re-read card");
      return false;
    }
    createKey();
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.println("Both keys failed: " + String(mfrc522.GetStatusCodeName(status)));
      mfrc522.PCD_StopCrypto1();
      return false;
    }
  }
  Serial.println("Sector 1 authenticated");

  // Zero blocks 4-6
  for (int i = 4; i <= 6; i++) {
    mfrc522.MIFARE_Write(i, emptyBlock, 16);
    Serial.println("Block " + String(i) + " cleared");
  }

  // Reset block 7 trailer: restore default keys and correct access bits.
  // Write the full 16 bytes directly (no read first) so this always works
  // even when MIFARE_Read fails for reasons related to corrupted access bits.
  {
    byte trailer7[16];
    for (int i = 0; i < 6; i++)  trailer7[i]      = 0xFF; // Key A = default
    trailer7[6] = 0xFF; trailer7[7] = 0x07; trailer7[8] = 0x80; trailer7[9] = 0x69; // access bits
    for (int i = 0; i < 6; i++)  trailer7[10 + i] = 0xFF; // Key B = default
    MFRC522::StatusCode s = mfrc522.MIFARE_Write(7, trailer7, 16);
    if (s == MFRC522::STATUS_OK) {
      Serial.println("Block 7 keys reset to default");
    } else {
      Serial.println("Block 7 reset failed: " + String(mfrc522.GetStatusCodeName(s)));
    }
  }

  // Power cycle to reset card state
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  mfrc522.PCD_AntennaOff();
  delay(100);
  mfrc522.PCD_AntennaOn();
  delay(100);

  // === SECTOR 2 (Blocks 8-10): default key ===
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    Serial.println("Could not re-read for sector 2");
    return false;
  }

  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 11, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK) {
    Serial.println("Sector 2 auth failed: " + String(mfrc522.GetStatusCodeName(status)));
    mfrc522.PCD_StopCrypto1();
    return false;
  }
  Serial.println("Sector 2 authenticated");

  for (int i = 8; i <= 10; i++) {
    mfrc522.MIFARE_Write(i, emptyBlock, 16);
    Serial.println("Block " + String(i) + " cleared");
  }

  Serial.println("=== Tag Reset Complete ===");
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  return true;
}

void handleSpoolReset()
{
  Serial.println("\n=== Waiting for tag to reset ===");

  unsigned long startTime = millis();
  while (millis() - startTime < 15000) {
    webServer.handleClient();
    if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
      String tagUid = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        if (mfrc522.uid.uidByte[i] < 0x10) tagUid += "0";
        tagUid += String(mfrc522.uid.uidByte[i], HEX);
      }
      tagUid.toUpperCase();
      Serial.println("Tag detected: " + tagUid);

      if (resetTag()) {
        tone(SPK_PIN, 1000, 150); delay(200);
        tone(SPK_PIN, 1000, 150); delay(200);
        noTone(SPK_PIN);
        webServer.send(200, "application/json", "{\"success\":true,\"uid\":\"" + tagUid + "\"}");
      } else {
        tone(SPK_PIN, 400, 500); delay(600); noTone(SPK_PIN);
        webServer.send(200, "application/json", "{\"success\":false,\"message\":\"Reset failed\"}");
      }
      return;
    }
    delay(50);
  }

  webServer.send(408, "application/json", "{\"success\":false,\"message\":\"Timeout - no tag detected\"}");
}

String extractValue(String json, String key) {
  int startIdx = json.indexOf("\"" + key + "\":\"");
  if(startIdx == -1) return "";
  startIdx += key.length() + 4;
  int endIdx = json.indexOf("\"", startIdx);
  return json.substring(startIdx, endIdx);
}
