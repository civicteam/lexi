import {SignKeyPair} from "tweetnacl";
import * as base64 from "@stablelib/base64";

const signKey: SignKeyPair = {
    publicKey: base64.decode("YS1wVA2MAEOHcloh/mIHkF15PR4ebnVVqyLhvJBrmhY="),
    secretKey: base64.decode("bYuMQUWUR2gV49x4GfAtfFsDMnhN14mp05Vuga8E5plhLXBUDYwAQ4dyWiH+YgeQXXk9Hh5udVWrIuG8kGuaFg=="),
}

export default signKey;
