using NUnit.Framework;

namespace PKDBF2Examples
{
    [TestFixture]
    class LowPasswordHasherTests
    {
        [Test]
        public void Low_Can_Hash_And_Verify()
        {
            var hash = LowPasswordHasher.HashPassword(Constants.SecurePassword);
            Assert.True(LowPasswordHasher.VerifyHashedPassword(hash,Constants.SecurePassword));
        }
    }
}
