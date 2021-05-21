/*
**
** Copyright 2019, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package android.security.jcic;

import javacard.framework.ISOException;
import javacard.framework.Util;

import static android.security.jcic.ICConstants.*;
import static android.security.jcic.ICConstants.LONG_SIZE;

public class ICUtil {

    /**
     * Get the sign bit of a given short (returns 0 or 1)
     */
    public static short sign(short a) {
        return (byte) ((a >>> (short) 15) & 1);
    }

    /**
     * Return the smaller short of two given values
     */
    public static short min(short a, short b) {
        if (a < b) {
            return a;
        }
        return b;
    }

    /**
     * Return the bigger short of two given values
     */
    public static short max(short a, short b) {
        if (a > b) {
            return a;
        }
        return b;
    }

    /**
     * Set the bit in a given bitfield array
     * 
     * @param bitField The bitfield array
     * @param flag     Index in the bitfield where the bit should be set
     * @param value    Sets bit to 0 or 1
     */
    public static void setBit(byte[] bitField, short flag, boolean value) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        if (value) {
            bitField[byteIndex] |= bitMask;
        } else {
            bitField[byteIndex] &= ~bitMask;
        }
    }

    /**
     * Get the value of a bit inside a bitfield
     * 
     * @param bitField The bitfield 
     * @param flag     Index in the bitfield that should be read
     * @return Value at the index (0 or 1)
     */
    public static boolean getBit(byte bitField, byte flag) {
        byte bitMask = (byte) ((byte) 1 << (short) (flag & 0x07));
        return bitMask == (byte) (bitField & bitMask);
    }

    /**
     * Set the bit in a given bitfield 
     * 
     * @param bitField The bitfield 
     * @param flag     Index in the bitfield where the bit should be set
     * @param value    Sets bit to 0 or 1
     */
    public static byte setBit(byte bitField, byte flag, boolean value) {
        byte bitMask = (byte) ((byte) 1 << (short) (flag & 0x07));
        if (value) {
            bitField |= bitMask;
        } else {
            bitField &= ~bitMask;
        }
        return bitField;
    }

    /**
     * Get the value of a bit inside a bitfield
     * 
     * @param bitField The bitfield array
     * @param flag     Index in the bitfield that should be read
     * @return Value at the index (0 or 1)
     */
    public static boolean getBit(byte[] bitField, short flag) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        return bitMask == (byte) (bitField[byteIndex] & bitMask);
    }

    /**
     * Compare two signed shorts as unsigned value. Returns true if n1 is truly
     * smaller, false otherwise.
     */
    public static boolean isLessThanAsUnsignedShort(short n1, short n2) {
        return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
    }
    
    /**
     * Fill a provided short array with a given value.
     */
    public static short shortArrayFillNonAtomic(short[] buffer, short offset, short len, short value) {
        len += offset;
        for (; offset < len; offset++) {
            buffer[offset] = value;
        }
        return offset;
    }
    
    /**
     * Increment a byte array by adding another byte array of same size or less than first byte array.
     * The addition is incremented in first byte array itself.
     * @param first byte array of short/integer/long value where addition will be updated
     * @param firstOffset start offset of first byte array
     * @param firstLen length of first byte array
     * @param second byte array of short/integer/long value
     * @param secondOffset start offset of second byte array
     * @param secondLen length of second byte array
     */
    public static void incrementByteArray(byte[] first, short firstOffset, byte firstLen, byte[] second, short secondOffset, byte secondLen) {
        byte index = (byte)(firstLen - 1);
        short sum;
        byte carry = (byte)0;
        while(index > (byte)0) {
            if(index >= secondLen) {
                short a1 = (short)(first[(short)(firstOffset + index)] & 0x00FF);
                short a2 = (short)(second[(short)(secondOffset + index - (short)2)] & 0x00FF);
                sum = (short)(carry + a1 + a2);
            } else {
                short a1 = (short)(first[(short)(firstOffset + index)] & 0x00FF);
                sum = (short)(carry + a1);
            }
            first[index] = (byte)sum;
            carry = (byte) (sum > 255 ? 1 : 0);
            index--;
        }
    }

    public static short constructCBORAccessControl(CBORDecoder cborDecoder, CBOREncoder cborEncoder,
                                             byte[] inBuff, short inOffset, short inLen,
                                             byte[] outBuff, short outOffset, short outLen,
                                             boolean withSecureUserId) {
        short numPairs = (short) 1;

        cborDecoder.init(inBuff, inOffset, inLen);
        cborEncoder.init(outBuff, outOffset, outLen);

        cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short id = cborDecoder.readInt8();
        boolean userAuthRequired = cborDecoder.readBoolean();
        cborDecoder.skipEntry(); //TimeoutMilis
        boolean secureUserIdPresent = false;
        if(userAuthRequired) {
            numPairs += 2;
            if(withSecureUserId) {
                byte intSize = cborDecoder.getIntegerSize();
                if(intSize == BYTE_SIZE) {
                    short secureUserId = cborDecoder.readInt8();
                    if(secureUserId > (short)0) {
                        secureUserIdPresent = true;
                        numPairs += 1;
                    }
                } else {
                    cborDecoder.skipEntry();
                    secureUserIdPresent = true;
                    numPairs += 1;
                }
            } else {
                cborDecoder.skipEntry();
            }
        } else {
            cborDecoder.skipEntry();
        }
        short readerCertSize = cborDecoder.readLength();
        if(readerCertSize > (short)0) {
            numPairs += 1;
        }
        cborEncoder.startMap(numPairs);
        cborEncoder.encodeTextString(STR_ID, (short)0, (short)STR_ID.length);
        if(id < (short)256) {
            cborEncoder.encodeUInt8((byte)id);
        } else {
            cborEncoder.encodeUInt16((short)id);
        }
        if(readerCertSize > (short)0) {
            //We have already traversed up to readerCertificate, so encode it from decoder
            cborEncoder.encodeTextString(STR_READER_CERTIFICATE, (short)0, (short)STR_READER_CERTIFICATE.length);
            //short encodeReaderCertOffset = cborEncoder.startByteString(readerCertSize);
            //Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), cborDecoder.getCurrentOffset(), outBuff, encodeReaderCertOffset, readerCertSize);
            //cborEncoder.increaseOffset(readerCertSize);
            cborEncoder.encodeByteString(cborDecoder.getBuffer(), cborDecoder.getCurrentOffset(), readerCertSize);
        }
        cborDecoder.reset();
        //Lets init decoder again to read timeoutMilis and secureUserId
        cborDecoder.init(inBuff, inOffset, inLen);
        cborDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        cborDecoder.skipEntry();//id
        userAuthRequired = cborDecoder.readBoolean();//userAuthRequired
        if(userAuthRequired) {
            cborEncoder.encodeTextString(STR_USER_AUTH_REQUIRED, (short)0, (short)STR_USER_AUTH_REQUIRED.length);
            cborEncoder.encodeBoolean(userAuthRequired);
            cborEncoder.encodeTextString(STR_TIMEOUT_MILIS, (short)0, (short)STR_TIMEOUT_MILIS.length);
            byte intSize = cborDecoder.getIntegerSize();
            if(intSize == BYTE_SIZE) {
                //outBuffer[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
                cborEncoder.encodeUInt8(cborDecoder.readInt8());
            } else if (intSize == SHORT_SIZE) {
                outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_TWO_BYTES;
                Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            } else if(intSize == INT_SIZE) {
                outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_FOUR_BYTES;
                Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            } else if(intSize == LONG_SIZE) {
                outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_EIGHT_BYTES;
                Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
            }

            if(withSecureUserId && secureUserIdPresent) {
                cborEncoder.encodeTextString(STR_SECURE_USER_ID, (short)0, (short)STR_SECURE_USER_ID.length);
                intSize = cborDecoder.getIntegerSize();
                if(intSize == BYTE_SIZE) {
                    //outBuffer[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_BYTE_STRING << 5) | CBORBase.ENCODED_ONE_BYTE;
                    cborEncoder.encodeUInt8(cborDecoder.readInt8());
                } else if (intSize == SHORT_SIZE) {
                    outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_TWO_BYTES;
                    Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
                } else if(intSize == INT_SIZE) {
                    outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_FOUR_BYTES;
                    Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
                } else if(intSize == LONG_SIZE) {
                    outBuff[cborEncoder.getCurrentOffsetAndIncrease((short) 1)] = (CBORBase.TYPE_UNSIGNED_INTEGER << 5) | CBORBase.ENCODED_EIGHT_BYTES;
                    Util.arrayCopyNonAtomic(inBuff, (short)(cborDecoder.getCurrentOffset() + 1), outBuff, cborEncoder.getCurrentOffsetAndIncrease(intSize), (short) intSize);
                }
            } else {
                cborDecoder.skipEntry();
            }
        }

        return cborEncoder.getCurrentOffset();
    }

    public static short readUint(CBORDecoder cborDecoder, byte[] outBuff, short outBuffOffset) {
        if(cborDecoder.getMajorType() != CBORBase.TYPE_UNSIGNED_INTEGER) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        byte intSize = cborDecoder.getIntegerSize();
        if(intSize == BYTE_SIZE) {
            outBuff[outBuffOffset] = cborDecoder.readInt8();
        } else if (intSize == SHORT_SIZE) {
            Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), (short)(cborDecoder.getCurrentOffset() + 1), outBuff, outBuffOffset, intSize);
            cborDecoder.increaseOffset((short)(intSize + 1));
        } else if(intSize == INT_SIZE) {
            Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), (short)(cborDecoder.getCurrentOffset() + 1), outBuff, outBuffOffset, intSize);
            cborDecoder.increaseOffset((short)(intSize + 1));
        } else if(intSize == LONG_SIZE) {
            Util.arrayCopyNonAtomic(cborDecoder.getBuffer(), (short)(cborDecoder.getCurrentOffset() + 1), outBuff, outBuffOffset, intSize);
            cborDecoder.increaseOffset((short)(intSize + 1));
        }
        return intSize;
    }

    public static byte calCborAdditionalLengthBytesFor(short size) {
        if (size < 24) {
            return 0;
        } else if (size <= 0xff) {
            return 1;
        }
        return 2;
    }

    public static byte calCborAdditionalLengthBytesFor(byte[] valueBuff, short valueOffset, short valueSize) {
        if(valueSize <= 0 || valueSize > 8) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if(valueSize == BYTE_SIZE) {
            if (valueBuff[valueOffset] < 24) {
                return 0;
            } else if (valueBuff[valueOffset] <= 0xff) {
                return 1;
            }
        }
        return (byte) valueSize;
    }
}
