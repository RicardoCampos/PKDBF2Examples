using NUnit.Framework;
using NUnit.Framework.Compatibility;

namespace PKDBF2Examples
{
    [TestFixture]
    class TestAllTheHashers
    {
        [Ignore("This takes a long time... you can run this to see them in action though")]
        [Test]
        public void Long_Running_Test()
        {
            string hash;
            const int iterations = 1000;
            var sw= new Stopwatch();
            sw.Start();
            for (var i=0; i < iterations; i++)
            {
                hash = LowPasswordHasher.HashPassword(Constants.SecurePassword);
            }
            sw.Stop();
            var low = sw.ElapsedMilliseconds/iterations;
            sw.Reset();
            sw.Start();
            for (var i = 0; i < iterations; i++)
            {
                hash = MediumPasswordHasher.HashPassword(Constants.SecurePassword);
            }
            sw.Stop();
            var medium = sw.ElapsedMilliseconds / iterations;
            sw.Reset();
            sw.Start();
            for (var i = 0; i < iterations; i++)
            {
                hash = HighPasswordHasher.HashPassword(Constants.SecurePassword);
            }
            sw.Stop();
            var high = sw.ElapsedMilliseconds / iterations;
            Assert.That(high >medium);
        }
    }
}