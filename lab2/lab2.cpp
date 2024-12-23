#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <locale>
#include <codecvt>
#include <fcntl.h>
#include <io.h>

using namespace std;

const int Nb = 4; // Number of columns (32-bit words) comprising the State. For AES, Nb = 4.
const int Nk = 4; // Number of 32-bit words comprising the Cipher Key. For AES-128, Nk = 4.
const int Nr = 10; // Number of rounds, which is a function of Nk and Nb (which is fixed). For AES-128, Nr = 10.

unsigned char state[4][4]; // Ensure this is declared globally
unsigned char RoundKey[240];
unsigned char Key[16];
unsigned char IV[16];
unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

int getSBoxValue(int num) {
    int sbox[256] = {
        // S-box values here
    };
    return sbox[num];
}

void KeyExpansion() {
    int i, j;
    unsigned char temp[4], k;

    // The first round key is the key itself.
    for (i = 0; i < Nk; i++) {
        RoundKey[i * 4] = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }

    // All other round keys are found from the previous round keys.
    while (i < (Nb * (Nr + 1))) {
        for (j = 0; j < 4; j++) {
            temp[j] = RoundKey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0) {
            // RotWord() and SubWord() operations
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);

            temp[0] = temp[0] ^ Rcon[i / Nk];
        }
        else if (Nk > 6 && i % Nk == 4) {
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);
        }
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
        i++;
    }
}

void AddRoundKey(int round) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}

void SubBytes() {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = getSBoxValue(state[i][j]);
        }
    }
}

void ShiftRows() {
    unsigned char temp;

    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

unsigned char xtime(unsigned char x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

void MixColumns() {
    unsigned char Tmp, Tm, t;
    for (int i = 0; i < 4; i++) {
        t = state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        Tm = state[0][i] ^ state[1][i];
        Tm = xtime(Tm);
        state[0][i] ^= Tm ^ Tmp;
        Tm = state[1][i] ^ state[2][i];
        Tm = xtime(Tm);
        state[1][i] ^= Tm ^ Tmp;
        Tm = state[2][i] ^ state[3][i];
        Tm = xtime(Tm);
        state[2][i] ^= Tm ^ Tmp;
        Tm = state[3][i] ^ t;
        Tm = xtime(Tm);
        state[3][i] ^= Tm ^ Tmp;
    }
}

void Cipher() {
    AddRoundKey(0);

    for (int round = 1; round < Nr; round++) {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }

    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
}

void XorWithIv(unsigned char* buf) {
    for (int i = 0; i < 16; i++) {
        buf[i] ^= IV[i];
    }
}

void AES_CBC_encrypt_buffer(unsigned char* buf, int length) {
    int i;
    for (i = 0; i < length; i += 16) {
        XorWithIv(buf + i);
        memcpy(state, buf + i, 16); // Initialize state with the input buffer
        Cipher();
        memcpy(buf + i, state, 16); // Copy the state to the output buffer
        memcpy(IV, buf + i, 16);
    }
}

int main() {
    // Set mode to support UTF-8
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stdin), _O_U8TEXT);

    wstring plaintext;
    wcout << L"Enter plaintext: ";
    getline(wcin, plaintext);

    wstring_convert<codecvt_utf8<wchar_t>> converter;
    string utf8_plaintext = converter.to_bytes(plaintext);

    wcout << L"Enter secret key (16 characters): ";
    wstring wkey;
    getline(wcin, wkey);
    string key = converter.to_bytes(wkey);
    memcpy(Key, key.c_str(), 16);

    wcout << L"Enter IV (16 characters): ";
    wstring wiv;
    getline(wcin, wiv);
    string iv = converter.to_bytes(wiv);
    memcpy(IV, iv.c_str(), 16);

    KeyExpansion();

    int length = utf8_plaintext.length();
    int padded_length = length + (16 - length % 16);
    vector<unsigned char> buffer(padded_length);
    memcpy(buffer.data(), utf8_plaintext.c_str(), length);

    AES_CBC_encrypt_buffer(buffer.data(), padded_length);

    wcout << L"Encrypted text: ";
    for (int i = 0; i < padded_length; i++) {
        wcout << hex << setw(2) << setfill(L'0') << (int)buffer[i];
    }
    wcout << endl;

    return 0;
}