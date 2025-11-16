namespace FrostYeti.Colors.Tests;

public class ArgbTests
{
    [Fact]
    public void Constructor_WithValidValue_SetsComponents()
    {
        var color = new Argb(0xFF112233);
        Assert.Equal(0xFF, color.A);
        Assert.Equal(0x11, color.R);
        Assert.Equal(0x22, color.G);
        Assert.Equal(0x33, color.B);
    }

    [Fact]
    public void Constructor_WithInvalidValue_ThrowsException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argb(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Argb(0x100000000));
    }

    [Fact]
    public void Constructor_WithComponents_SetsCorrectValue()
    {
        var color = new Argb(0xFF, 0x11, 0x22, 0x33);
        Assert.Equal(0xFF, color.A);
        Assert.Equal(0x11, color.R);
        Assert.Equal(0x22, color.G);
        Assert.Equal(0x33, color.B);
    }

    [Fact]
    public void DefaultConstructor_CreatesTransparentBlack()
    {
#pragma warning disable SA1129 // Do not use default value type constructor

        var color = new Argb();

        Assert.Equal(0, color.A);
        Assert.Equal(0, color.R);
        Assert.Equal(0, color.G);
        Assert.Equal(0, color.B);
    }

    [Fact]
    public void Deconstruct_ReturnsCorrectComponents()
    {
        var color = new Argb(0xFF, 0x11, 0x22, 0x33);
        (byte a, byte r, byte g, byte b) = color;
        Assert.Equal(0xFF, a);
        Assert.Equal(0x11, r);
        Assert.Equal(0x22, g);
        Assert.Equal(0x33, b);
    }

    [Fact]
    public void Equals_WithSameValues_ReturnsTrue()
    {
        var color1 = new Argb(0xFF112233);
        var color2 = new Argb(0xFF112233);
        Assert.True(color1.Equals(color2));
        Assert.True(color1.Equals((IArgb)color2));
        Assert.True(color1.Equals((object)color2));
    }

    [Fact]
    public void GetHashCode_ReturnsSameValueForEqualColors()
    {
        var color1 = new Argb(0xFF112233);
        var color2 = new Argb(0xFF112233);
        Assert.Equal(color1.GetHashCode(), color2.GetHashCode());
    }
}