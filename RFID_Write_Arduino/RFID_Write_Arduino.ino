#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 9
#define SS_PIN 18          // SDA PIN

// MFRC522 인스턴스 생성
MFRC522 mfrc522(SS_PIN, RST_PIN);

void setup() {
  Serial.begin(9600);        
  SPI.begin();               
  mfrc522.PCD_Init();
  Serial.println(F("Write personal data on a MIFARE PICC "));
}

void loop() {

  // Prepare key - all keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  // RFID Tag가 인식 되면 이하 코드를 실행함.
  // 인식된 태그가 없으면 루프의 초기로 돌아감
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // ID 값이 정상인지 확인 후 이하 코드 실행
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  /*
  // RFID Tag의 UID 출력
  Serial.print(F("Card UID:"));
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  // PICC 카드의 Type을 출력
  Serial.print(F(" PICC type: "));   // Dump PICC type
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  */

  // 태그 내부 데이터 출력
  readData(key);

  byte buffer[34];
  byte len;

  // Timeout 시간 지정
  // 20초 만큼 입력을 기다림.
  Serial.setTimeout(20000L);

  // Data 입력
  Serial.println(F("장소의 이름을 입력해주세요. 장소 입력 마지막 # 입력"));
  len = Serial.readBytesUntil('#', (char *) buffer, 30) ; // read family name from serial
  Serial.println("");
  // 버퍼에 입력될 값의 나머지 부분은 Space로 Padding 채움
  for (byte i = len; i < 30; i++) buffer[i] = ' ';
  
  writeData(key, buffer);

  Serial.println(" ");
  mfrc522.PICC_HaltA(); // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD

}

void writeData(MFRC522::MIFARE_Key key, byte buffer[]) {
  // 한 블럭에 16바이트까지 저장 가능
  // 2블럭에 저장하여 32byte까지 저장 가능하도록 구현
  // 한글은 글자당 2byte이므로 최대 16글자까지 입력 가능

  // 상태코드 입력 변수
  MFRC522::StatusCode status;

  for(byte block=1; block < 3; block++) {
    Serial.print("block Number : ");
    Serial.println(block);

    // PCD 인증
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("PCD_Authenticate() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return;
    }
    else Serial.println(F("PCD_Authenticate() success: "));

    // Write block
    status = mfrc522.MIFARE_Write(block, &buffer[block * 16 - 16], 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return;
    }
    else Serial.println(F("MIFARE_Write() success: "));
  }
}

void readData(MFRC522::MIFARE_Key key) {
  Serial.println(F("***** 태그가 감지됨 *****"));

  byte len = 18;

  byte buffer[32];
  byte buffer1[18];
  byte buffer2[18];

  // 상태코드 입력 변수
  MFRC522::StatusCode status;

  // 첫 번째 블럭 읽기
  byte block = 1;

  // 인증
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid)); //line 834
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // 데이터 읽기
  status = mfrc522.MIFARE_Read(block, buffer1, &len);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Reading failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // 두 번째 블럭 읽기
  block = 2;

  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid)); //line 834
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // 데이터 읽기
  status = mfrc522.MIFARE_Read(block, buffer2, &len);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Reading failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // 1번 버퍼와 2번 버퍼 합치기
  for(byte i = 0; i <= 31; i++) {
    if(i < 16) {
      buffer[i] = buffer1[i];
    } else {
      buffer[i] = buffer2[i-16];
    }
    Serial.print(buffer[i]);
    Serial.write(buffer[i]);
  }
  Serial.println();
  Serial.println("***** 태그 정보 끝 *****");
}
