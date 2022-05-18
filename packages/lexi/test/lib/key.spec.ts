import {newNonce} from "../../src/lib/key";
import {expect} from "chai";

describe("lib/key.ts", () => {
    it("Call newNonce and see if it's valid", async() => {
        expect(newNonce()).to.have.length(24);
    })
})
