using Xunit;

namespace FrostYeti.Colors.Tests;

public class ColorTests
{
    [Fact]
    public void Constructor_FromSystemDrawingColor_SetsCorrectValues()
    {
        // Arrange
        var systemColor = System.Drawing.Color.FromArgb(255, 100, 150, 200);

        // Act
        var color = new Color(systemColor);

        // Assert
        Assert.Equal(100, color.R);
        Assert.Equal(150, color.G);
        Assert.Equal(200, color.B);
        Assert.Equal(255, (byte)color.A);
    }

    [Fact]
    public void Constructor_FromSystemDrawingColor_WithTransparency_SetsCorrectValues()
    {
        // Arrange
        var systemColor = System.Drawing.Color.FromArgb(128, 100, 150, 200);

        // Act
        var color = new Color(systemColor);

        // Assert
        Assert.Equal(100, color.R);
        Assert.Equal(150, color.G);
        Assert.Equal(200, color.B);
        Assert.Equal((Alpha)128, color.A);
    }

    [Fact]
    public void DefaultConstructor_SetsExpectedValues()
    {
        // Act
#pragma warning disable SA1129 // Do not use default value type constructor
        var color = new Color();

        // Assert
        Assert.Equal(0, color.R);
        Assert.Equal(0, color.G);
        Assert.Equal(0, color.B);
        Assert.Equal((Alpha)255, color.A); // Opaque
    }

    [Fact]
    public void Equals_SameValues_ReturnsTrue()
    {
        // Arrange
        var color1 = new Color(100, 150, 200, 255);
        var color2 = new Color(100, 150, 200, 255);

        // Act & Assert
        Assert.True(color1.Equals(color2));
        Assert.True(color1 == color2);
    }

    [Fact]
    public void Equals_DifferentValues_ReturnsFalse()
    {
        // Arrange
        var color1 = new Color(100, 150, 200, 255);
        var color2 = new Color(100, 150, 201, 255);

        // Act & Assert
        Assert.False(color1.Equals(color2));
        Assert.True(color1 != color2);
    }

    [Fact]
    public void Deconstruct_ThreeParameters_SetsCorrectValues()
    {
        // Arrange
        var color = new Color(100, 150, 200);

        // Act
        var (r, g, b) = color;

        // Assert
        Assert.Equal(100, r);
        Assert.Equal(150, g);
        Assert.Equal(200, b);
    }

    [Fact]
    public void Deconstruct_FourParameters_SetsCorrectValues()
    {
        // Arrange
        var color = new Color(100, 150, 200, 128);

        // Act
        var (r, g, b, a) = color;

        // Assert
        Assert.Equal(100, r);
        Assert.Equal(150, g);
        Assert.Equal(200, b);
        Assert.Equal(128, a);
    }

    [Fact]
    public void GetHashCode_SameValues_ReturnsSameHashCode()
    {
        // Arrange
        var color1 = new Color(100, 150, 200, 255);
        var color2 = new Color(100, 150, 200, 255);

        // Act
        var hash1 = color1.GetHashCode();
        var hash2 = color2.GetHashCode();

        // Assert
        Assert.Equal(hash1, hash2);
    }
}