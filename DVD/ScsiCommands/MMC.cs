namespace Aaru.Decryption.ScsiCommands
{
    public class MMC
    {
        public bool InvalidateAgid(out byte[] buffer, out byte[] senseBuffer, CssKeyClass keyClass, byte agid,
                                   uint timeout, out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[0];

            cdb[0]  = (byte)ScsiCommands.ReportKey;
            cdb[7]  = (byte)keyClass;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)((byte)CssReportKeyFormat.InvalidateAgid ^ (agid << 6));

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.In, out duration,
                                        out bool sense);

            Error = LastError != 0;

            AaruConsole.DebugWriteLine("SCSI Device",
                                       "INVALIDATE AGID (AGID: {1}, Sense: {2}, Last Error: {3}) took {0} ms.",
                                       duration, agid, sense, LastError);

            return sense;
        }

        public bool ReportAgidCssCppm(out byte[] buffer, out byte[] senseBuffer, CssKeyClass keyClass, byte agid,
                                      uint timeout, out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[8];

            cdb[0]  = (byte)ScsiCommands.ReportKey;
            cdb[7]  = (byte)keyClass;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)((byte)CssReportKeyFormat.AgidForCssCppm ^ (agid << 6));

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.In, out duration,
                                        out bool sense);

            Error = LastError != 0;

            AaruConsole.DebugWriteLine("SCSI Device",
                                       "REPORT AGID CSS/CPPM (AGID: {1}, Sense: {2}, Last Error: {3}) took {0} ms.",
                                       duration, agid, sense, LastError);

            return sense;
        }

        public bool ReportKey1(out byte[] buffer, out byte[] senseBuffer, CssKeyClass keyClass, byte agid, uint timeout,
                               out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[12];

            cdb[0]  = (byte)ScsiCommands.ReportKey;
            cdb[7]  = (byte)keyClass;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)((byte)CssReportKeyFormat.Key1 ^ (agid << 6));

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.In, out duration,
                                        out bool sense);

            Error = LastError != 0;

            AaruConsole.DebugWriteLine("SCSI Device",
                                       "REPORT KEY1 (AGID: {1}, Sense: {2}, Last Error: {3}) took {0} ms.", duration,
                                       agid, sense, LastError);

            return sense;
        }

        public bool ReportChallenge(out byte[] buffer, out byte[] senseBuffer, CssKeyClass keyClass, byte agid,
                                    uint timeout, out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[16];

            cdb[0]  = (byte)ScsiCommands.ReportKey;
            cdb[7]  = (byte)keyClass;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)((byte)CssReportKeyFormat.ChallengeKey ^ (agid << 6));

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.In, out duration,
                                        out bool sense);

            Error = LastError != 0;

            AaruConsole.DebugWriteLine("SCSI Device",
                                       "REPORT CHALLENGE (AGID: {1}, Sense: {2}, Last Error: {3}) took {0} ms.",
                                       duration, agid, sense, LastError);

            return sense;
        }

        public bool SendChallenge(out byte[] buffer, out byte[] senseBuffer, CssKeyClass keyClass, byte agid,
                                  byte[] challengeKey, uint timeout, out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[16];

            cdb[0]  = (byte)ScsiCommands.SendKey;
            cdb[7]  = (byte)keyClass;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)(((byte)CssSendKeyFormat.ChallengeKey ^ (agid << 6)));

            buffer[0]  = (byte)(((buffer.Length - 2) & 0xFF00) >> 8);
            buffer[1]  = (byte)((buffer.Length - 2) & 0xFF);
            buffer[4]  = challengeKey[9];
            buffer[5]  = challengeKey[8];
            buffer[6]  = challengeKey[7];
            buffer[7]  = challengeKey[6];
            buffer[8]  = challengeKey[5];
            buffer[9]  = challengeKey[4];
            buffer[10] = challengeKey[3];
            buffer[11] = challengeKey[2];
            buffer[12] = challengeKey[1];
            buffer[13] = challengeKey[0];

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.Out, out duration,
                                        out bool sense);

            Error = LastError != 0;

            AaruConsole.DebugWriteLine("SCSI Device",
                                       "SEND CHALLENGE (AGID: {1}, Challenge {2}, Sense: {3}, Last Error: {4}) took {0} ms.",
                                       duration, agid, challengeKey, sense, LastError);

            return sense;
        }

        public bool SendKey2(out byte[] buffer, out byte[] senseBuffer, CssKeyClass keyClass, byte agid, byte[] key2,
                             uint timeout, out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[12];

            cdb[0]  = (byte)ScsiCommands.SendKey;
            cdb[7]  = (byte)keyClass;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)((byte)CssSendKeyFormat.Key2 ^ (agid << 6));

            buffer[0] = (byte)(((buffer.Length - 2) & 0xFF00) >> 8);
            buffer[1] = (byte)((buffer.Length - 2) & 0xFF);
            buffer[4] = key2[4];
            buffer[5] = key2[3];
            buffer[6] = key2[2];
            buffer[7] = key2[1];
            buffer[8] = key2[0];

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.Out, out duration,
                                        out bool sense);

            Error = LastError != 0;

            AaruConsole.DebugWriteLine("SCSI Device",
                                       "SEND CHALLENGE (AGID: {1}, KEY2 {2}, Sense: {3}, Last Error: {4}) took {0} ms.",
                                       duration, agid, key2, sense, LastError);

            return sense;
        }

        /// <summary>Returns the encrypted disc key of the MMC logical unit</summary>
        /// <returns><c>true</c> if the command failed and <paramref name="senseBuffer" /> contains the sense buffer.</returns>
        /// <param name="buffer">Buffer where the bus key will be stored</param>
        /// <param name="senseBuffer">Sense buffer.</param>
        /// <param name="agid">The Authentication Grant ID to use</param>
        /// <param name="timeout">Timeout in seconds.</param>
        /// <param name="duration">Duration in milliseconds it took for the device to execute the command.</param>
        public bool GetDiscKey(out byte[] buffer, out byte[] senseBuffer, byte agid, uint timeout, out double duration)
        {
            senseBuffer = new byte[32];
            byte[] cdb = new byte[12];
            buffer = new byte[2052];

            cdb[0]  = (byte)ScsiCommands.ReadDiscStructure;
            cdb[1]  = ((byte)MmcDiscStructureMediaType.Dvd & 0x0F);
            cdb[6]  = 0;
            cdb[7]  = (byte)MmcDiscStructureFormat.DiscKey;
            cdb[8]  = (byte)((buffer.Length & 0xFF00) >> 8);
            cdb[9]  = (byte)(buffer.Length & 0xFF);
            cdb[10] = (byte)((agid & 0x03) << 6);

            LastError = SendScsiCommand(cdb, ref buffer, out senseBuffer, timeout, ScsiDirection.In, out duration,
                                        out bool sense);

            Error = LastError != 0;

            return (sense);
        }

        /// <summary>Returns the bus key of the MMC logical unit</summary>
        /// <returns><c>true</c> if the command failed and <paramref name="senseBuffer" /> contains the sense buffer.</returns>
        /// <param name="buffer">Buffer where the bus key will be stored</param>
        /// <param name="senseBuffer">Sense buffer.</param>
        /// <param name="agid">The Authentication Grant ID to use</param>
        /// <param name="protectionType">The type of protection the logical unit reports</param>
        /// <param name="timeout">Timeout in seconds.</param>
        /// <param name="duration">Duration in milliseconds it took for the device to execute the command.</param>
        public bool GetBusKey(out byte[] buffer, out byte[] senseBuffer, out byte agid,
                              Decoders.DVD.CopyrightType protectionType, uint timeout, out double duration)
        {
            duration    = 0;
            buffer      = new byte[0];
            senseBuffer = new byte[32];
            agid        = 0;
            bool sense = false;

            const byte keySize       = 5;
            const byte challengeSize = 2 * keySize;

            byte[] challenge = new byte[challengeSize];
            byte[] key1      = new byte[keySize];
            byte[] key2      = new byte[keySize];
            byte[] keyCheck  = new byte[keySize];
            byte   variant   = 0;

            for(byte i = 0; i < 4; i++)
            {
                // Invalidate AGID to reset any previous drive communications
                agid = i;

                sense = InvalidateAgid(out buffer, out senseBuffer, CssKeyClass.DvdCssCppmOrCprm, agid, timeout,
                                       out duration);

                // Get AGID
                if(protectionType == Decoders.DVD.CopyrightType.CSS)
                {
                    sense = ReportAgidCssCppm(out buffer, out senseBuffer, CssKeyClass.DvdCssCppmOrCprm, agid, timeout,
                                              out duration);
                }

                if(!sense)
                {
                    agid = (byte)(buffer[7] >> 6);

                    break;
                }
            }

            if(sense)
            {
                return true;
            }

            for(byte i = 0; i < challengeSize; i++)
                challenge[i] = i;

            sense = SendChallenge(out buffer, out senseBuffer, CssKeyClass.DvdCssCppmOrCprm, agid, challenge, timeout,
                                  out duration);

            if(sense)
            {
                return true;
            }

            sense = ReportKey1(out buffer, out senseBuffer, CssKeyClass.DvdCssCppmOrCprm, agid, timeout, out duration);

            if(sense)
            {
                return true;
            }

            for(byte i = 0; i < keySize; i++)
                key1[i] = buffer[8 - i];

            for(byte i = 0; i < 32; i++)
            {
                Decoders.DVD.CSS_CPRM.EncryptKey(Decoders.DVD.DVDCSSKeyType.Key1, i, challenge, out keyCheck);

                if(key1.SequenceEqual(keyCheck))
                {
                    variant = i;

                    break;
                }

                if(i >= 31)
                {
                    return true;
                }
            }

            sense = ReportChallenge(out buffer, out senseBuffer, CssKeyClass.DvdCssCppmOrCprm, agid, timeout,
                                    out duration);

            if(sense)
            {
                return true;
            }

            for(byte i = 0; i < 10; i++)
                challenge[i] = buffer[13 - i];

            Decoders.DVD.CSS_CPRM.EncryptKey(Decoders.DVD.DVDCSSKeyType.Key2, variant, challenge, out key2);

            sense = SendKey2(out buffer, out senseBuffer, CssKeyClass.DvdCssCppmOrCprm, agid, key2, timeout,
                             out duration);

            if(sense)
            {
                return true;
            }

            key1.CopyTo(challenge, 0);
            key2.CopyTo(challenge, key1.Length);

            Decoders.DVD.CSS_CPRM.EncryptKey(Decoders.DVD.DVDCSSKeyType.BusKey, variant, challenge, out buffer);

            return sense;
        }
    }
}