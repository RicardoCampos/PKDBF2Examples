namespace System.Security.Cryptography
{
    using Text;

    /// <remarks>
    /// Drop in replacement for Rfc2898DeriveBytes but using SHA512
    /// using some non-internal classes
    /// </remarks>
    [System.Runtime.InteropServices.ComVisible(true)]
    public class Rfc2898DeriveBytes_HMACSHA512 : DeriveBytes
    {
        private byte[] _buffer;
        private byte[] _salt;
        private readonly HMACSHA512 _hmacsha512;  // The pseudo-random generator function used in PBKDF2

        private uint _iterations;
        private uint _block;
        private int _startIndex;
        private int _endIndex;
        private static RNGCryptoServiceProvider _rng;
        private static RNGCryptoServiceProvider StaticRandomNumberGenerator
        {
            get { return _rng ?? (_rng = new RNGCryptoServiceProvider()); }
        }

        private const int BlockSize = 20;

        public Rfc2898DeriveBytes_HMACSHA512(string password, int saltSize) : this(password, saltSize, 1000) { }
        [SecuritySafeCritical]
        public Rfc2898DeriveBytes_HMACSHA512(string password, int saltSize, int iterations)
        {
            if (saltSize < 0)
                throw new ArgumentOutOfRangeException("saltSize");

            byte[] salt = new byte[saltSize];
            StaticRandomNumberGenerator.GetBytes(salt);

            Salt = salt;
            IterationCount = iterations;
            _hmacsha512 = new HMACSHA512(new UTF8Encoding(false).GetBytes(password));
            Initialize();
        }

        public Rfc2898DeriveBytes_HMACSHA512(string password, byte[] salt) : this(password, salt, 1000) { }

        public Rfc2898DeriveBytes_HMACSHA512(string password, byte[] salt, int iterations) : this(new UTF8Encoding(false).GetBytes(password), salt, iterations) { }
        [SecuritySafeCritical]
        public Rfc2898DeriveBytes_HMACSHA512(byte[] password, byte[] salt, int iterations)
        {
            Salt = salt;
            IterationCount = iterations;
            _hmacsha512 = new HMACSHA512(password);
            Initialize();
        }

        //
        // public properties 
        //

        public int IterationCount
        {
            get { return (int)_iterations; }
            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException("value");
                _iterations = (uint)value;
                Initialize();
            }
        }

        public byte[] Salt
        {
            get { return (byte[])_salt.Clone(); }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                if (value.Length < 8)
                    throw new ArgumentException();
                _salt = (byte[])value.Clone();
                Initialize();
            }
        }

        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
                throw new ArgumentOutOfRangeException("cb");
            var password = new byte[cb];

            var offset = 0;
            var size = _endIndex - _startIndex;
            if (size > 0)
            {
                if (cb >= size)
                {
                    Buffer.BlockCopy(_buffer, _startIndex, password, 0, size);
                    _startIndex = _endIndex = 0;
                    offset += size;
                }
                else
                {
                    Buffer.BlockCopy(_buffer, _startIndex, password, 0, cb);
                    _startIndex += cb;
                    return password;
                }
            }

            while (offset < cb)
            {
                var block = Func();
                var remainder = cb - offset;
                if (remainder > BlockSize)
                {
                    Buffer.BlockCopy(block, 0, password, offset, BlockSize);
                    offset += BlockSize;
                }
                else
                {
                    Buffer.BlockCopy(block, 0, password, offset, remainder);
                    offset += remainder;
                    Buffer.BlockCopy(block, remainder, _buffer, _startIndex, BlockSize - remainder);
                    _endIndex += (BlockSize - remainder);
                    return password;
                }
            }
            return password;
        }

        public override void Reset()
        {
            Initialize();
        }

        private void Initialize()
        {
            if (_buffer != null)
                Array.Clear(_buffer, 0, _buffer.Length);
            _buffer = new byte[BlockSize];
            _block = 1;
            _startIndex = _endIndex = 0;
        }
        internal static byte[] Int(uint i)
        {
            var b = BitConverter.GetBytes(i);
            byte[] littleEndianBytes = { b[3], b[2], b[1], b[0] };
            return BitConverter.IsLittleEndian ? littleEndianBytes : b;
        }
        // This function is defined as follows : 
        // Func (S, i) = HMAC(S || i) | HMAC2(S || i) | ... | HMAC(iterations) (S || i)
        // where i is the block number. 
        private byte[] Func()
        {
            var intBlock = Int(_block);
            _hmacsha512.TransformBlock(_salt, 0, _salt.Length, _salt, 0);
            _hmacsha512.TransformFinalBlock(intBlock, 0, intBlock.Length);
            var temp = _hmacsha512.Hash;
            _hmacsha512.Initialize();

            var ret = temp;
            for (var i = 2; i <= _iterations; i++)
            {
                temp = _hmacsha512.ComputeHash(temp);
                for (var j = 0; j < BlockSize; j++)
                {
                    ret[j] ^= temp[j];
                }
            }

            // increment the block count.
            _block++;
            return ret;
        }
    }
}