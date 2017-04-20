public class OTP
{
    public const int SECRET_LENGTH = 20;
    private const string
	MSG_SECRETLENGTH = "Secret must be at least 20 bytes",
	MSG_COUNTER_MINVALUE = "Counter min value is 1";

    public OTP()
    {
    }

    private static int[] dd = new int[10] { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 }; 

    private byte[] secretKey = new byte[SECRET_LENGTH] 
    {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43
    };

    private ulong counter = 0x0000000000000001;

    private static int checksum(int Code_Digits) 
    {
	int d1 = (Code_Digits/1000000) % 10;
	int d2 = (Code_Digits/100000) % 10;
	int d3 = (Code_Digits/10000) % 10;
	int d4 = (Code_Digits/1000) % 10;
	int d5 = (Code_Digits/100) % 10;
	int d6 = (Code_Digits/10) % 10;
	int d7 = Code_Digits % 10;
	return (10 - ((dd[d1]+d2+dd[d3]+d4+dd[d5]+d6+dd[d7]) % 10) ) % 10;
    }

    /// <summary>
    /// Formats the OTP. This is the OTP algorithm.
    /// </summary>
    /// <param name="hmac">HMAC value</param>
    /// <returns>8 digits OTP</returns>
    private static string FormatOTP(byte[] hmac)
    {
	int offset =  hmac[19] & 0xf ;
	int bin_code = (hmac[offset]   & 0x7f) << 24
		| (hmac[offset+1] & 0xff) << 16
		| (hmac[offset+2] & 0xff) <<  8
		| (hmac[offset+3] & 0xff) ;
	int Code_Digits = bin_code % 10000000;
	int csum = checksum(Code_Digits);
	int OTP = Code_Digits * 10 + csum;

	return string.Format("{0:d08}", OTP);
    }

    public byte[] CounterArray
    {
	get
	{
	    return BitConverter.GetBytes(counter);
	}

	set
	{
	    counter = BitConverter.ToUInt64(value, 0);
	}
    }

    /// <summary>
    /// Sets the OTP secret
    /// </summary>
    public byte[] Secret
    {
	set
	{
	    if (value.Length < SECRET_LENGTH)
	    {
		throw new Exception(MSG_SECRETLENGTH);
	    }

	    secretKey = value;
	}
    }

    /// <summary>
    /// Gets the current OTP value
    /// </summary>
    /// <returns>8 digits OTP</returns>
    public string GetCurrentOTP()
    {
	HmacSha1 hmacSha1 = new HmacSha1();

	hmacSha1.Init(secretKey);
	hmacSha1.Update(CounterArray);
		
	byte[] hmac_result = hmacSha1.Final();

	return FormatOTP(hmac_result);
    }

    /// <summary>
    /// Gets the next OTP value
    /// </summary>
    /// <returns>8 digits OTP</returns>
    public string GetNextOTP()	
    {
	// increment the counter
	++counter;

	return GetCurrentOTP();
    }

    /// <summary>
    /// Gets/sets the counter value
    /// </summary>
    public ulong Counter
    {
	get
	{
	    return counter;
	}

	set
	{
	    counter = value;
	}
    }
}