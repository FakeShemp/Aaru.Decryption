﻿using System;
using System.Linq;

namespace Aaru.Decryption
{
    public class CSS
    {
        static readonly byte[] encryptTable0 =
        {
            0xB7, 0xF4, 0x82, 0x57, 0xDA, 0x4D, 0xDB, 0xE2, 0x2F, 0x52, 0x1A, 0xA8, 0x68, 0x5A, 0x8A, 0xFF, 0xFB, 0x0E,
            0x6D, 0x35, 0xF7, 0x5C, 0x76, 0x12, 0xCE, 0x25, 0x79, 0x29, 0x39, 0x62, 0x08, 0x24, 0xA5, 0x85, 0x7B, 0x56,
            0x01, 0x23, 0x68, 0xCF, 0x0A, 0xE2, 0x5A, 0xED, 0x3D, 0x59, 0xB0, 0xA9, 0xB0, 0x2C, 0xF2, 0xB8, 0xEF, 0x32,
            0xA9, 0x40, 0x80, 0x71, 0xAF, 0x1E, 0xDE, 0x8F, 0x58, 0x88, 0xB8, 0x3A, 0xD0, 0xFC, 0xC4, 0x1E, 0xB5, 0xA0,
            0xBB, 0x3B, 0x0F, 0x01, 0x7E, 0x1F, 0x9F, 0xD9, 0xAA, 0xB8, 0x3D, 0x9D, 0x74, 0x1E, 0x25, 0xDB, 0x37, 0x56,
            0x8F, 0x16, 0xBA, 0x49, 0x2B, 0xAC, 0xD0, 0xBD, 0x95, 0x20, 0xBE, 0x7A, 0x28, 0xD0, 0x51, 0x64, 0x63, 0x1C,
            0x7F, 0x66, 0x10, 0xBB, 0xC4, 0x56, 0x1A, 0x04, 0x6E, 0x0A, 0xEC, 0x9C, 0xD6, 0xE8, 0x9A, 0x7A, 0xCF, 0x8C,
            0xDB, 0xB1, 0xEF, 0x71, 0xDE, 0x31, 0xFF, 0x54, 0x3E, 0x5E, 0x07, 0x69, 0x96, 0xB0, 0xCF, 0xDD, 0x9E, 0x47,
            0xC7, 0x96, 0x8F, 0xE4, 0x2B, 0x59, 0xC6, 0xEE, 0xB9, 0x86, 0x9A, 0x64, 0x84, 0x72, 0xE2, 0x5B, 0xA2, 0x96,
            0x58, 0x99, 0x50, 0x03, 0xF5, 0x38, 0x4D, 0x02, 0x7D, 0xE7, 0x7D, 0x75, 0xA7, 0xB8, 0x67, 0x87, 0x84, 0x3F,
            0x1D, 0x11, 0xE5, 0xFC, 0x1E, 0xD3, 0x83, 0x16, 0xA5, 0x29, 0xF6, 0xC7, 0x15, 0x61, 0x29, 0x1A, 0x43, 0x4F,
            0x9B, 0xAF, 0xC5, 0x87, 0x34, 0x6C, 0x0F, 0x3B, 0xA8, 0x1D, 0x45, 0x58, 0x25, 0xDC, 0xA8, 0xA3, 0x3B, 0xD1,
            0x79, 0x1B, 0x48, 0xF2, 0xE9, 0x93, 0x1F, 0xFC, 0xDB, 0x2A, 0x90, 0xA9, 0x8A, 0x3D, 0x39, 0x18, 0xA3, 0x8E,
            0x58, 0x6C, 0xE0, 0x12, 0xBB, 0x25, 0xCD, 0x71, 0x22, 0xA2, 0x64, 0xC6, 0xE7, 0xFB, 0xAD, 0x94, 0x77, 0x04,
            0x9A, 0x39, 0xCF, 0x7C
        };

        static readonly byte[] encryptTable1 =
        {
            0x8C, 0x47, 0xB0, 0xE1, 0xEB, 0xFC, 0xEB, 0x56, 0x10, 0xE5, 0x2C, 0x1A, 0x5D, 0xEF, 0xBE, 0x4F, 0x08, 0x75,
            0x97, 0x4B, 0x0E, 0x25, 0x8E, 0x6E, 0x39, 0x5A, 0x87, 0x53, 0xC4, 0x1F, 0xF4, 0x5C, 0x4E, 0xE6, 0x99, 0x30,
            0xE0, 0x42, 0x88, 0xAB, 0xE5, 0x85, 0xBC, 0x8F, 0xD8, 0x3C, 0x54, 0xC9, 0x53, 0x47, 0x18, 0xD6, 0x06, 0x5B,
            0x41, 0x2C, 0x67, 0x1E, 0x41, 0x74, 0x33, 0xE2, 0xB4, 0xE0, 0x23, 0x29, 0x42, 0xEA, 0x55, 0x0F, 0x25, 0xB4,
            0x24, 0x2C, 0x99, 0x13, 0xEB, 0x0A, 0x0B, 0xC9, 0xF9, 0x63, 0x67, 0x43, 0x2D, 0xC7, 0x7D, 0x07, 0x60, 0x89,
            0xD1, 0xCC, 0xE7, 0x94, 0x77, 0x74, 0x9B, 0x7E, 0xD7, 0xE6, 0xFF, 0xBB, 0x68, 0x14, 0x1E, 0xA3, 0x25, 0xDE,
            0x3A, 0xA3, 0x54, 0x7B, 0x87, 0x9D, 0x50, 0xCA, 0x27, 0xC3, 0xA4, 0x50, 0x91, 0x27, 0xD4, 0xB0, 0x82, 0x41,
            0x97, 0x79, 0x94, 0x82, 0xAC, 0xC7, 0x8E, 0xA5, 0x4E, 0xAA, 0x78, 0x9E, 0xE0, 0x42, 0xBA, 0x28, 0xEA, 0xB7,
            0x74, 0xAD, 0x35, 0xDA, 0x92, 0x60, 0x7E, 0xD2, 0x0E, 0xB9, 0x24, 0x5E, 0x39, 0x4F, 0x5E, 0x63, 0x09, 0xB5,
            0xFA, 0xBF, 0xF1, 0x22, 0x55, 0x1C, 0xE2, 0x25, 0xDB, 0xC5, 0xD8, 0x50, 0x03, 0x98, 0xC4, 0xAC, 0x2E, 0x11,
            0xB4, 0x38, 0x4D, 0xD0, 0xB9, 0xFC, 0x2D, 0x3C, 0x08, 0x04, 0x5A, 0xEF, 0xCE, 0x32, 0xFB, 0x4C, 0x92, 0x1E,
            0x4B, 0xFB, 0x1A, 0xD0, 0xE2, 0x3E, 0xDA, 0x6E, 0x7C, 0x4D, 0x56, 0xC3, 0x3F, 0x42, 0xB1, 0x3A, 0x23, 0x4D,
            0x6E, 0x84, 0x56, 0x68, 0xF4, 0x0E, 0x03, 0x64, 0xD0, 0xA9, 0x92, 0x2F, 0x8B, 0xBC, 0x39, 0x9C, 0xAC, 0x09,
            0x5E, 0xEE, 0xE5, 0x97, 0xBF, 0xA5, 0xCE, 0xFA, 0x28, 0x2C, 0x6D, 0x4F, 0xEF, 0x77, 0xAA, 0x1B, 0x79, 0x8E,
            0x97, 0xB4, 0xC3, 0xF4
        };

        static readonly byte[] encryptTable2 =
        {
            0xB7, 0x75, 0x81, 0xD5, 0xDC, 0xCA, 0xDE, 0x66, 0x23, 0xDF, 0x15, 0x26, 0x62, 0xD1, 0x83, 0x77, 0xE3, 0x97,
            0x76, 0xAF, 0xE9, 0xC3, 0x6B, 0x8E, 0xDA, 0xB0, 0x6E, 0xBF, 0x2B, 0xF1, 0x19, 0xB4, 0x95, 0x34, 0x48, 0xE4,
            0x37, 0x94, 0x5D, 0x7B, 0x36, 0x5F, 0x65, 0x53, 0x07, 0xE2, 0x89, 0x11, 0x98, 0x85, 0xD9, 0x12, 0xC1, 0x9D,
            0x84, 0xEC, 0xA4, 0xD4, 0x88, 0xB8, 0xFC, 0x2C, 0x79, 0x28, 0xD8, 0xDB, 0xB3, 0x1E, 0xA2, 0xF9, 0xD0, 0x44,
            0xD7, 0xD6, 0x60, 0xEF, 0x14, 0xF4, 0xF6, 0x31, 0xD2, 0x41, 0x46, 0x67, 0x0A, 0xE1, 0x58, 0x27, 0x43, 0xA3,
            0xF8, 0xE0, 0xC8, 0xBA, 0x5A, 0x5C, 0x80, 0x6C, 0xC6, 0xF2, 0xE8, 0xAD, 0x7D, 0x04, 0x0D, 0xB9, 0x3C, 0xC2,
            0x25, 0xBD, 0x49, 0x63, 0x8C, 0x9F, 0x51, 0xCE, 0x20, 0xC5, 0xA1, 0x50, 0x92, 0x2D, 0xDD, 0xBC, 0x8D, 0x4F,
            0x9A, 0x71, 0x2F, 0x30, 0x1D, 0x73, 0x39, 0x13, 0xFB, 0x1A, 0xCB, 0x24, 0x59, 0xFE, 0x05, 0x96, 0x57, 0x0F,
            0x1F, 0xCF, 0x54, 0xBE, 0xF5, 0x06, 0x1B, 0xB2, 0x6D, 0xD3, 0x4D, 0x32, 0x56, 0x21, 0x33, 0x0B, 0x52, 0xE7,
            0xAB, 0xEB, 0xA6, 0x74, 0x00, 0x4C, 0xB1, 0x7F, 0x82, 0x99, 0x87, 0x0E, 0x5E, 0xC0, 0x8F, 0xEE, 0x6F, 0x55,
            0xF3, 0x7E, 0x08, 0x90, 0xFA, 0xB6, 0x64, 0x70, 0x47, 0x4A, 0x17, 0xA7, 0xB5, 0x40, 0x8A, 0x38, 0xE5, 0x68,
            0x3E, 0x8B, 0x69, 0xAA, 0x9B, 0x42, 0xA5, 0x10, 0x01, 0x35, 0xFD, 0x61, 0x9E, 0xE6, 0x16, 0x9C, 0x86, 0xED,
            0xCD, 0x2E, 0xFF, 0xC4, 0x5B, 0xA0, 0xAE, 0xCC, 0x4B, 0x3B, 0x03, 0xBB, 0x1C, 0x2A, 0xAC, 0x0C, 0x3F, 0x93,
            0xC7, 0x72, 0x7A, 0x09, 0x22, 0x3D, 0x45, 0x78, 0xA9, 0xA8, 0xEA, 0xC9, 0x6A, 0xF7, 0x29, 0x91, 0xF0, 0x02,
            0x18, 0x3A, 0x4E, 0x7C
        };

        static readonly byte[] encryptTable3 =
        {
            0x73, 0x51, 0x95, 0xE1, 0x12, 0xE4, 0xC0, 0x58, 0xEE, 0xF2, 0x08, 0x1B, 0xA9, 0xFA, 0x98, 0x4C, 0xA7, 0x33,
            0xE2, 0x1B, 0xA7, 0x6D, 0xF5, 0x30, 0x97, 0x1D, 0xF3, 0x02, 0x60, 0x5A, 0x82, 0x0F, 0x91, 0xD0, 0x9C, 0x10,
            0x39, 0x7A, 0x83, 0x85, 0x3B, 0xB2, 0xB8, 0xAE, 0x0C, 0x09, 0x52, 0xEA, 0x1C, 0xE1, 0x8D, 0x66, 0x4F, 0xF3,
            0xDA, 0x92, 0x29, 0xB9, 0xD5, 0xC5, 0x77, 0x47, 0x22, 0x53, 0x14, 0xF7, 0xAF, 0x22, 0x64, 0xDF, 0xC6, 0x72,
            0x12, 0xF3, 0x75, 0xDA, 0xD7, 0xD7, 0xE5, 0x02, 0x9E, 0xED, 0xDA, 0xDB, 0x4C, 0x47, 0xCE, 0x91, 0x06, 0x06,
            0x6D, 0x55, 0x8B, 0x19, 0xC9, 0xEF, 0x8C, 0x80, 0x1A, 0x0E, 0xEE, 0x4B, 0xAB, 0xF2, 0x08, 0x5C, 0xE9, 0x37,
            0x26, 0x5E, 0x9A, 0x90, 0x00, 0xF3, 0x0D, 0xB2, 0xA6, 0xA3, 0xF7, 0x26, 0x17, 0x48, 0x88, 0xC9, 0x0E, 0x2C,
            0xC9, 0x02, 0xE7, 0x18, 0x05, 0x4B, 0xF3, 0x39, 0xE1, 0x20, 0x02, 0x0D, 0x40, 0xC7, 0xCA, 0xB9, 0x48, 0x30,
            0x57, 0x67, 0xCC, 0x06, 0xBF, 0xAC, 0x81, 0x08, 0x24, 0x7A, 0xD4, 0x8B, 0x19, 0x8E, 0xAC, 0xB4, 0x5A, 0x0F,
            0x73, 0x13, 0xAC, 0x9E, 0xDA, 0xB6, 0xB8, 0x96, 0x5B, 0x60, 0x88, 0xE1, 0x81, 0x3F, 0x07, 0x86, 0x37, 0x2D,
            0x79, 0x14, 0x52, 0xEA, 0x73, 0xDF, 0x3D, 0x09, 0xC8, 0x25, 0x48, 0xD8, 0x75, 0x60, 0x9A, 0x08, 0x27, 0x4A,
            0x2C, 0xB9, 0xA8, 0x8B, 0x8A, 0x73, 0x62, 0x37, 0x16, 0x02, 0xBD, 0xC1, 0x0E, 0x56, 0x54, 0x3E, 0x14, 0x5F,
            0x8C, 0x8F, 0x6E, 0x75, 0x1C, 0x07, 0x39, 0x7B, 0x4B, 0xDB, 0xD3, 0x4B, 0x1E, 0xC8, 0x7E, 0xFE, 0x3E, 0x72,
            0x16, 0x83, 0x7D, 0xEE, 0xF5, 0xCA, 0xC5, 0x18, 0xF9, 0xD8, 0x68, 0xAB, 0x38, 0x85, 0xA8, 0xF0, 0xA1, 0x73,
            0x9F, 0x5D, 0x19, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x72, 0x39, 0x25, 0x67, 0x26,
            0x6D, 0x71, 0x36, 0x77, 0x3C, 0x20, 0x62, 0x23, 0x68, 0x74, 0xC3, 0x82, 0xC9, 0x15, 0x57, 0x16, 0x5D, 0x81
        };

        static readonly byte[,] permutationChallenge =
        {
            {
                1, 3, 0, 7, 5, 2, 9, 6, 4, 8
            },
            {
                6, 1, 9, 3, 8, 5, 7, 4, 0, 2
            },
            {
                4, 0, 3, 5, 7, 2, 8, 6, 1, 9
            }
        };

        static readonly byte[,] permutationVariant =
        {
            {
                0x0a, 0x08, 0x0e, 0x0c, 0x0b, 0x09, 0x0f, 0x0d, 0x1a, 0x18, 0x1e, 0x1c, 0x1b, 0x19, 0x1f, 0x1d, 0x02,
                0x00, 0x06, 0x04, 0x03, 0x01, 0x07, 0x05, 0x12, 0x10, 0x16, 0x14, 0x13, 0x11, 0x17, 0x15
            },
            {
                0x12, 0x1a, 0x16, 0x1e, 0x02, 0x0a, 0x06, 0x0e, 0x10, 0x18, 0x14, 0x1c, 0x00, 0x08, 0x04, 0x0c, 0x13,
                0x1b, 0x17, 0x1f, 0x03, 0x0b, 0x07, 0x0f, 0x11, 0x19, 0x15, 0x1d, 0x01, 0x09, 0x05, 0x0d
            }
        };

        static readonly byte[] variants =
        {
            0xB7, 0x74, 0x85, 0xD0, 0xCC, 0xDB, 0xCA, 0x73, 0x03, 0xFE, 0x31, 0x03, 0x52, 0xE0, 0xB7, 0x42, 0x63, 0x16,
            0xF2, 0x2A, 0x79, 0x52, 0xFF, 0x1B, 0x7A, 0x11, 0xCA, 0x1A, 0x9B, 0x40, 0xAD, 0x01
        };

        static readonly byte[] secret =
        {
            0x55, 0xD6, 0xC4, 0xC5, 0x28
        };

        public static DiscKey? DecodeDiscKey(byte[] response, byte[] busKey)
        {
            if(response?.Length != 2052 ||
               busKey?.Length   != 5)
                return null;

            byte[] key = response.Skip(4).Take(2048).ToArray();

            for(uint i = 0; i < key.Length; i++)
                key[i] ^= busKey[4 - (i % busKey.Length)];

            return new DiscKey
            {
                DataLength = (ushort)((response[0] << 8) + response[1]),
                Reserved1  = response[2],
                Reserved2  = response[3],
                Key        = key
            };
        }

        public static void EncryptKey(DVDCSSKeyType keyType, uint variant, byte[] challenge, out byte[] key)
        {
            byte[] bits    = new byte[30];
            byte[] scratch = new byte[10];
            byte   index   = sizeof(byte) * 30;
            byte[] temp1   = new byte[5];
            byte[] temp2   = new byte[5];
            byte   carry   = 0;
            int    term    = 0;
            byte   cse;
            byte   lfsr0_o;
            byte   lfsr1_o;
            byte   combined;
            key = new byte[5];

            for(int i = 9; i >= 0; --i)
                scratch[i] = challenge[permutationChallenge[(uint)keyType, i]];

            byte cssVariant = (byte)(keyType == 0 ? variant : permutationVariant[(uint)keyType - 1, variant]);

            for(int i = 5; --i >= 0;)
                temp1[i] = (byte)(scratch[5 + i] ^ secret[i] ^ encryptTable2[i]);

            uint lfsr0 = (uint)((temp1[0] << 17) | (temp1[1] << 9) | ((temp1[2] & ~7) << 1) | 8 | (temp1[2] & 7));
            uint lfsr1 = (uint)((temp1[3] << 9)  | 0x100           | temp1[4]);

            do
            {
                byte val = 0;

                for(int bit = 0; bit < 8; ++bit)
                {
                    lfsr0_o = (byte)(((lfsr0 >> 24) ^ (lfsr0 >> 21) ^ (lfsr0 >> 20) ^ (lfsr0 >> 12)) & 1);
                    lfsr0   = (lfsr0 << 1) | lfsr0_o;

                    lfsr1_o = (byte)(((lfsr1 >> 16) ^ (lfsr1 >> 2)) & 1);
                    lfsr1   = (lfsr1 << 1) | lfsr1_o;

                    combined =  (byte)(Convert.ToByte(lfsr1_o == 0) + carry + Convert.ToByte(lfsr0_o == 0));
                    carry    =  (byte)((combined >> 1) & 1);
                    val      |= (byte)((combined & 1) << bit);
                }

                bits[--index] = val;
            } while(index > 0);

            cse = (byte)(variants[cssVariant] ^ encryptTable2[cssVariant]);

            index = 0;
            term  = 0;

            for(int i = 5; --i >= 0; term = scratch[i])
            {
                index = (byte)(bits[25 + i]         ^ scratch[i]);
                index = (byte)(encryptTable1[index] ^ ~encryptTable2[index] ^ cse);

                temp1[i] = (byte)(encryptTable2[index] ^ encryptTable3[index] ^ term);
            }

            temp1[4] ^= temp1[0];

            term = 0;

            for(int i = 5; --i >= 0; term = temp1[i])
            {
                index = (byte)(bits[20 + i]         ^ temp1[i]);
                index = (byte)(encryptTable1[index] ^ ~encryptTable2[index] ^ cse);

                temp2[i] = (byte)(encryptTable2[index] ^ encryptTable3[index] ^ term);
            }

            temp2[4] ^= temp2[0];

            term = 0;

            for(int i = 5; --i >= 0; term = temp2[i])
            {
                index = (byte)(bits[15 + i]         ^ temp2[i]);
                index = (byte)(encryptTable1[index] ^ ~encryptTable2[index] ^ cse);
                index = (byte)(encryptTable2[index] ^ encryptTable3[index]  ^ term);

                temp1[i] = (byte)(encryptTable0[index] ^ encryptTable2[index]);
            }

            temp1[4] ^= temp1[0];

            term = 0;

            for(int i = 5; --i >= 0; term = temp1[i])
            {
                index = (byte)(bits[10 + i]         ^ temp1[i]);
                index = (byte)(encryptTable1[index] ^ ~encryptTable2[index] ^ cse);
                index = (byte)(encryptTable2[index] ^ encryptTable3[index]  ^ term);

                temp2[i] = (byte)(encryptTable0[index] ^ encryptTable2[index]);
            }

            temp2[4] ^= temp2[0];

            term = 0;

            for(int i = 5; --i >= 0; term = temp2[i])
            {
                index = (byte)(bits[5 + i]          ^ temp2[i]);
                index = (byte)(encryptTable1[index] ^ ~encryptTable2[index] ^ cse);

                temp1[i] = (byte)(encryptTable2[index] ^ encryptTable3[index] ^ term);
            }

            temp1[4] ^= temp1[0];

            term = 0;

            for(int i = 5; --i >= 0; term = temp1[i])
            {
                index = (byte)(bits[i]              ^ temp1[i]);
                index = (byte)(encryptTable1[index] ^ ~encryptTable2[index] ^ cse);

                key[i] = (byte)(encryptTable2[index] ^ encryptTable3[index] ^ term);
            }
        }
    }
}