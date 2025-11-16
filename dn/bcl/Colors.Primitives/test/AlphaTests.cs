namespace FrostYeti.Colors.Tests;

public class AlphaTests
{
    [Fact]
    public void Constructor_WithValidValue_SetsProperty()
    {
        var alpha = new Alpha(0.5);
        Assert.Equal(0.5, alpha.A);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    public void Constructor_WithInvalidValue_ThrowsArgumentOutOfRange(double value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Alpha(value));
    }

    [Fact]
    public void DefaultConstructor_SetsOpaqueValue()
    {
        Alpha alpha = 1d;
        Assert.Equal(1.0, alpha.A);
    }

    [Fact]
    public void Opaque_ReturnsFullAlpha()
    {
        Assert.Equal(1.0, Alpha.Opaque.A);
    }

    [Fact]
    public void Transparent_ReturnsZeroAlpha()
    {
        Assert.Equal(0.0, Alpha.Transparent.A);
    }

    [Fact]
    public void ImplicitConversion_FromDouble_CreatesCorrectAlpha()
    {
        Alpha alpha = 0.5;
        Assert.Equal(0.5, alpha.A);
    }

    [Fact]
    public void ImplicitConversion_ToDouble_ReturnsCorrectValue()
    {
        Alpha alpha = new(0.5);
        double value = alpha;
        Assert.Equal(0.5, value);
    }

    [Fact]
    public void ImplicitConversion_FromByte_CreatesCorrectAlpha()
    {
        Alpha alpha = (byte)128;
        Assert.Equal(128.0 / 255.0, alpha.A);
    }

    [Fact]
    public void ImplicitConversion_ToByte_ReturnsCorrectValue()
    {
        Alpha alpha = new(0.5);
        byte value = alpha;
        Assert.Equal((byte)127, value);
    }

    [Fact]
    public void Equals_WithSameValue_ReturnsTrue()
    {
        var alpha1 = new Alpha(0.5);
        var alpha2 = new Alpha(0.5);
        Assert.True(alpha1.Equals(alpha2));
    }

    [Fact]
    public void Equals_WithDifferentValue_ReturnsFalse()
    {
        var alpha1 = new Alpha(0.5);
        var alpha2 = new Alpha(0.7);
        Assert.False(alpha1.Equals(alpha2));
    }
}