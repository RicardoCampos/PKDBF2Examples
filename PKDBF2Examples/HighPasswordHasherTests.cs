using NUnit.Framework;

namespace PKDBF2Examples
{
    [TestFixture]
    class HighPasswordHasherTests
    {
        [Test]
        public void High_Can_Hash_And_Verify()
        {
            var hash = HighPasswordHasher.HashPassword(Constants.SecurePassword);
            Assert.True(HighPasswordHasher.VerifyHashedPassword(hash, Constants.SecurePassword));
        }
    }
}