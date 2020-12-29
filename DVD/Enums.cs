namespace Aaru.Decryption
{
    public enum CssKeyClass : byte
    {
        DvdCssCppmOrCprm = 0, RewritableSecurityServicesA = 1
    }
    
    public enum CssReportKeyFormat : byte
    {
        AgidForCssCppm = 0x00, ChallengeKey   = 0x01, Key1     = 0x02,
        TitleKey       = 0x04, Asf            = 0x05, RpcState = 0x08,
        AgidForCprm    = 0x11, InvalidateAgid = 0x3f
    }
    
    public enum CssSendKeyFormat : byte
    {
        ChallengeKey   = 0x01, Key2 = 0x03, RpcStructure = 0x06,
        InvalidateAgid = 0x3f
    }
}