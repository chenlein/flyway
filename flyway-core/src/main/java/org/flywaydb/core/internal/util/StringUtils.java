/*
 * Copyright 2010-2018 Boxfuse GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.flywaydb.core.internal.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Various string-related utilities.
 */
public class StringUtils {
    private static final char[] WHITESPACE_CHARS = {' ', '\t', '\n', '\f', '\r'};

    /**
     * Prevents instantiation.
     */
    private StringUtils() {
        // Do nothing.
    }

    /**
     * Trims or pads (with spaces) this string, so it has this exact length.
     *
     * @param str    The string to adjust. {@code null} is treated as an empty string.
     * @param length The exact length to reach.
     * @return The adjusted string.
     */
    public static String trimOrPad(String str, int length) {
        return trimOrPad(str, length, ' ');
    }

    /**
     * Trims or pads this string, so it has this exact length.
     *
     * @param str     The string to adjust. {@code null} is treated as an empty string.
     * @param length  The exact length to reach.
     * @param padChar The padding character.
     * @return The adjusted string.
     */
    public static String trimOrPad(String str, int length, char padChar) {
        StringBuilder result;
        if (str == null) {
            result = new StringBuilder();
        } else {
            result = new StringBuilder(str);
        }

        if (result.length() > length) {
            return result.substring(0, length);
        }

        while (result.length() < length) {
            result.append(padChar);
        }
        return result.toString();
    }

    /**
     * <p>Checks if the String contains only unicode digits. A decimal point is not a unicode digit and returns
     * false.</p> <p/> <p>{@code null} will return {@code false}. An empty String ("") will return {@code true}.</p>
     * <p/>
     * <pre>
     * StringUtils.isNumeric(null)   = false
     * StringUtils.isNumeric("")     = true
     * StringUtils.isNumeric("  ")   = false
     * StringUtils.isNumeric("123")  = true
     * StringUtils.isNumeric("12 3") = false
     * StringUtils.isNumeric("ab2c") = false
     * StringUtils.isNumeric("12-3") = false
     * StringUtils.isNumeric("12.3") = false
     * </pre>
     *
     * @param str the String to check, may be null
     * @return {@code true} if only contains digits, and is non-null
     */
    public static boolean isNumeric(String str) {
        return str != null && str.matches("\\d*");
    }

    /**
     * Replaces all sequences of whitespace by a single blank. Ex.: "&nbsp;&nbsp;&nbsp;&nbsp;" -> " "
     *
     * @param str The string to analyse.
     * @return The input string, with all whitespace collapsed.
     */
    public static String collapseWhitespace(String str) {
        StringBuilder result = new StringBuilder();
        char previous = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            boolean whitespace = false;
            for (char w : WHITESPACE_CHARS) {
                if (c == w) {
                    if (previous != ' ') {
                        result.append(' ');
                    }
                    previous = ' ';
                    whitespace = true;
                    break;
                }
            }
            if (!whitespace) {
                result.append(c);
                previous = c;
            }
        }
        return result.toString();
    }

    /**
     * Returns the first n characters from this string, where n = count. If the string is shorter, the entire string
     * will be returned. If the string is longer, it will be truncated.
     *
     * @param str   The string to parse.
     * @param count The amount of characters to return.
     * @return The first n characters from this string, where n = count.
     */
    public static String left(String str, int count) {
        if (str == null) {
            return null;
        }

        if (str.length() < count) {
            return str;
        }

        return str.substring(0, count);
    }

    /**
     * Replaces all occurrances of this originalToken in this string with this replacementToken.
     *
     * @param str              The string to process.
     * @param originalToken    The token to replace.
     * @param replacementToken The replacement.
     * @return The transformed str.
     */
    public static String replaceAll(String str, String originalToken, String replacementToken) {
        return str.replaceAll(Pattern.quote(originalToken), Matcher.quoteReplacement(replacementToken));
    }

    /**
     * Checks whether this string is not {@code null} and not <i>empty</i>.
     *
     * @param str The string to check.
     * @return {@code true} if it has content, {@code false} if it is {@code null} or blank.
     */
    public static boolean hasLength(String str) {
        return str != null && str.length() > 0;
    }

    /**
     * Turns this string array in one comma-delimited string.
     *
     * @param strings The array to process.
     * @return The new comma-delimited string. An empty string if {@code strings} is empty. {@code null} if strings is {@code null}.
     */
    public static String arrayToCommaDelimitedString(Object[] strings) {
        return arrayToDelimitedString(",", strings);
    }

    /**
     * Turns this string array in one delimited string.
     *
     * @param delimiter The delimiter to use.
     * @param strings   The array to process.
     * @return The new delimited string. An empty string if {@code strings} is empty. {@code null} if strings is {@code null}.
     */
    public static String arrayToDelimitedString(String delimiter, Object[] strings) {
        if (strings == null) {
            return null;
        }

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < strings.length; i++) {
            if (i > 0) {
                builder.append(delimiter);
            }
            builder.append(String.valueOf(strings[i]));
        }
        return builder.toString();
    }

    /**
     * Checks whether this string isn't {@code null} and contains at least one non-blank character.
     *
     * @param s The string to check.
     * @return {@code true} if it has text, {@code false} if not.
     */
    public static boolean hasText(String s) {
        return (s != null) && (s.trim().length() > 0);
    }

    /**
     * Splits this string into an array using these delimiters.
     *
     * @param str        The string to split.
     * @param delimiters The delimiters to use.
     * @return The resulting array.
     */
    public static String[] tokenizeToStringArray(String str, String delimiters) {
        if (str == null) {
            return null;
        }
        Collection<String> tokens = tokenizeToStringCollection(str, delimiters);
        return tokens.toArray(new String[0]);
    }

    /**
     * Splits this string into a collection using these delimiters.
     *
     * @param str        The string to split.
     * @param delimiters The delimiters to use.
     * @return The resulting array.
     */
    public static Collection<String> tokenizeToStringCollection(String str, String delimiters) {
        if (str == null) {
            return null;
        }
        List<String> tokens = new ArrayList<>(str.length() / 5);
        char[] delimiterChars = delimiters.toCharArray();
        int start = 0;
        int end = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            boolean delimiter = false;
            for (char d : delimiterChars) {
                if (c == d) {
                    tokens.add(str.substring(start, end));
                    start = i + 1;
                    end = start;
                    delimiter = true;
                    break;
                }
            }
            if (!delimiter) {
                if (i == start && c == ' ') {
                    start++;
                    end++;
                }
                if (i >= start && c != ' ') {
                    end = i + 1;
                }
            }
        }
        if (start < end) {
            tokens.add(str.substring(start, end));
        }
        return tokens;
    }

    /**
     * Counts the number of occurrences of this token in this string.
     *
     * @param str   The string to analyse.
     * @param token The token to look for.
     * @return The number of occurrences.
     */
    public static int countOccurrencesOf(String str, String token) {
        if (str == null || token == null || str.length() == 0 || token.length() == 0) {
            return 0;
        }
        int count = 0;
        int pos = 0;
        int idx;
        while ((idx = str.indexOf(token, pos)) != -1) {
            ++count;
            pos = idx + token.length();
        }
        return count;
    }

    /**
     * Replace all occurences of a substring within a string with
     * another string.
     *
     * @param inString   String to examine
     * @param oldPattern String to replace
     * @param newPattern String to insert
     * @return a String with the replacements
     */
    public static String replace(String inString, String oldPattern, String newPattern) {
        if (!hasLength(inString) || !hasLength(oldPattern) || newPattern == null) {
            return inString;
        }
        StringBuilder sb = new StringBuilder();
        int pos = 0; // our position in the old string
        int index = inString.indexOf(oldPattern);
        // the index of an occurrence we've found, or -1
        int patLen = oldPattern.length();
        while (index >= 0) {
            sb.append(inString, pos, index);
            sb.append(newPattern);
            pos = index + patLen;
            index = inString.indexOf(oldPattern, pos);
        }
        sb.append(inString.substring(pos));
        // remember to append any characters to the right of a match
        return sb.toString();
    }

    /**
     * Replaces this group matched from this regex against this source with this replacement.
     *
     * @param source         The source string.
     * @param regex          The regex to use.
     * @param groupToReplace The number of the matching group to replace.
     * @param replacement    The replacement.
     * @return The resulting string with the group replaced.
     */
    public static String replaceGroup(String source, String regex, int groupToReplace, String replacement) {
        return replaceGroup(source, regex, groupToReplace, 1, replacement);
    }

    private static String replaceGroup(String source, String regex, int groupToReplace, int groupOccurrence, String replacement) {
        Matcher m = Pattern.compile(regex).matcher(source);
        for (int i = 0; i < groupOccurrence; i++)
            if (!m.find()) return source; // pattern not met, may also throw an exception here
        return new StringBuilder(source).replace(m.start(groupToReplace), m.end(groupToReplace), replacement).toString();
    }

    /**
     * Convenience method to return a Collection as a comma-delimited
     * String. E.g. useful for {@code toString()} implementations.
     *
     * @param collection the Collection to analyse
     * @return The comma-delimited String.
     */
    public static String collectionToCommaDelimitedString(Collection<?> collection) {
        return collectionToDelimitedString(collection, ", ");
    }

    /**
     * Convenience method to return a Collection as a delimited
     * String. E.g. useful for {@code toString()} implementations.
     *
     * @param collection the Collection to analyse
     * @param delimiter  The delimiter.
     * @return The delimited String.
     */
    public static String collectionToDelimitedString(Collection<?> collection, String delimiter) {
        if (collection == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            sb.append(it.next());
            if (it.hasNext()) {
                sb.append(delimiter);
            }
        }
        return sb.toString();
    }

    /**
     * Trim leading whitespace from the given String.
     *
     * @param str the String to check
     * @return the trimmed String
     * @see java.lang.Character#isWhitespace
     */
    public static String trimLeadingWhitespace(String str) {
        if (!hasLength(str)) {
            return str;
        }
        StringBuilder buf = new StringBuilder(str);
        while (buf.length() > 0 && Character.isWhitespace(buf.charAt(0))) {
            buf.deleteCharAt(0);
        }
        return buf.toString();
    }

    /**
     * Trim trailing whitespace from the given String.
     *
     * @param str the String to check
     * @return the trimmed String
     * @see java.lang.Character#isWhitespace
     */
    public static String trimTrailingWhitespace(String str) {
        if (!hasLength(str)) {
            return str;
        }
        StringBuilder buf = new StringBuilder(str);
        while (buf.length() > 0 && Character.isWhitespace(buf.charAt(buf.length() - 1))) {
            buf.deleteCharAt(buf.length() - 1);
        }
        return buf.toString();
    }

    /**
     * Checks whether this strings both begins with this prefix and ends withs either of these suffixes.
     *
     * @param str      The string to check.
     * @param prefix   The prefix.
     * @param suffixes The suffixes.
     * @return {@code true} if it does, {@code false} if not.
     */
    public static boolean startsAndEndsWith(String str, String prefix, String... suffixes) {
        if (StringUtils.hasLength(prefix) && !str.startsWith(prefix)) {
            return false;
        }
        for (String suffix : suffixes) {
            if (str.endsWith(suffix) && (str.length() > (prefix + suffix).length())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Trim the trailing linebreak (if any) from this string.
     * @param str The string.
     * @return The string without trailing linebreak.
     */
    public static String trimLineBreak(String str) {
        if (!hasLength(str)) {
            return str;
        }
        StringBuilder buf = new StringBuilder(str);
        while (buf.length() > 0 && isLineBreakCharacter(buf.charAt(buf.length() - 1))) {
            buf.deleteCharAt(buf.length() - 1);
        }
        return buf.toString();
    }

    /**
     * Checks whether this character is a linebreak character.
     * @param ch The character
     * @return {@code true} if it is, {@code false} if not.
     */
    private static boolean isLineBreakCharacter(char ch) {
        return '\n' == ch || '\r' == ch;
    }
}