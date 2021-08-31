package utils;

import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class PGPMessageHelper {
    public static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
            throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
            throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }
        while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
            throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    public static byte[] getLineSeparator()
    {
        String nl = Strings.lineSeparator();
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++)
        {
            nlBytes[i] = (byte)nl.charAt(i);
        }

        return nlBytes;
    }

    public static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
    {
        int    end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end]))
        {
            end--;
        }

        return end + 1;
    }

    public static boolean isLineEnding(byte b)
    {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line)
    {
        int    end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end]))
        {
            end--;
        }

        return end + 1;
    }

    public static boolean isWhiteSpace(byte b)
    {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }
}
