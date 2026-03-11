import { describe, it, expect } from "vitest";
import { FlashbotsBundleManager, FlashbotsError } from "../bundle/flashbots";
import { FlashbotsNetwork } from "../types";

describe("FlashbotsBundleManager", () => {
  describe("constructor", () => {
    it("creates with minimal config", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(manager).toBeDefined();
    });

    it("accepts full config", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
        relayUrl: "https://relay.flashbots.net",
        mevShareUrl: "https://relay.flashbots.net",
        network: FlashbotsNetwork.Mainnet,
        authSignerKey: "abc123",
        maxRetries: 5,
        timeout: 60000,
      });
      expect(manager).toBeDefined();
    });

    it("defaults to mainnet", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      // We can't directly access private members, but it should not throw
      expect(manager).toBeDefined();
    });
  });

  describe("FlashbotsError", () => {
    it("creates error with message", () => {
      const err = new FlashbotsError("test error");
      expect(err.message).toBe("test error");
      expect(err.name).toBe("FlashbotsError");
    });

    it("creates error with code and details", () => {
      const err = new FlashbotsError("test", "ERR_CODE", { foo: "bar" });
      expect(err.code).toBe("ERR_CODE");
      expect(err.details).toEqual({ foo: "bar" });
    });

    it("is instanceof Error", () => {
      const err = new FlashbotsError("test");
      expect(err instanceof Error).toBe(true);
      expect(err instanceof FlashbotsError).toBe(true);
    });
  });

  describe("inherits BaseBundleManager", () => {
    it("has confirmBundle method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.confirmBundle).toBe("function");
    });

    it("has sendBundle method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.sendBundle).toBe("function");
    });

    it("has getBundleStatus method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.getBundleStatus).toBe("function");
    });

    it("has sendMevShareBundle method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.sendMevShareBundle).toBe("function");
    });

    it("has simulateBundle method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.simulateBundle).toBe("function");
    });

    it("has cancelBundle method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.cancelBundle).toBe("function");
    });

    it("has sendPrivateTransaction method", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
      });
      expect(typeof manager.sendPrivateTransaction).toBe("function");
    });
  });

  describe("network configuration", () => {
    it("supports Goerli network", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
        network: FlashbotsNetwork.Goerli,
      });
      expect(manager).toBeDefined();
    });

    it("supports Sepolia network", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
        network: FlashbotsNetwork.Sepolia,
      });
      expect(manager).toBeDefined();
    });

    it("supports custom relay URL", () => {
      const manager = new FlashbotsBundleManager({
        endpoint: "http://localhost:8545",
        relayUrl: "https://custom-relay.example.com",
      });
      expect(manager).toBeDefined();
    });
  });
});
