using NUnit.Framework;

namespace PKDBF2Examples
{
    [TestFixture]
    class MediumPasswordHasherTests
    {
        [Test]
        public void Medium_Can_Hash_And_Verify()
        {
            var hash = MediumPasswordHasher.HashPassword(Constants.SecurePassword);
            Assert.True(MediumPasswordHasher.VerifyHashedPassword(hash, Constants.SecurePassword));
        }
    }
}