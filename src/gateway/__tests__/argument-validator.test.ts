import { describe, it, expect } from "vitest";
import { createArgumentValidator } from "../argument-validator.js";
import type { ToolCategoryName } from "../types.js";

describe("ArgumentValidator", () => {
  const validator = createArgumentValidator();

  // ─── exec ───────────────────────────────────────────────────────────

  describe("exec", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("exec", {
        command: "ls",
        args: ["-la", "/tmp"],
        cwd: "/home/user",
        env: { PATH: "/usr/bin", HOME: "/home/user" },
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts valid args with only required fields", () => {
      const result = validator.validate("exec", { command: "echo" });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("rejects missing command", () => {
      const result = validator.validate("exec", { args: ["--help"] });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects empty string command", () => {
      const result = validator.validate("exec", { command: "" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects wrong type for command (number)", () => {
      const result = validator.validate("exec", { command: 42 });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects wrong type for args (string instead of array)", () => {
      const result = validator.validate("exec", { command: "ls", args: "--all" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  // ─── fs_write ───────────────────────────────────────────────────────

  describe("fs_write", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("fs_write", {
        path: "/tmp/out.txt",
        content: "hello world",
        mode: "create",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts valid args with only required fields", () => {
      const result = validator.validate("fs_write", { path: "/tmp/out.txt" });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts all valid mode enum values", () => {
      for (const mode of ["create", "overwrite", "append", "delete"]) {
        const result = validator.validate("fs_write", { path: "/f", mode });
        expect(result.valid).toBe(true);
      }
    });

    it("rejects missing path", () => {
      const result = validator.validate("fs_write", { content: "data" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects empty string path", () => {
      const result = validator.validate("fs_write", { path: "" });
      expect(result.valid).toBe(false);
    });

    it("rejects invalid mode enum value", () => {
      const result = validator.validate("fs_write", {
        path: "/tmp/out.txt",
        mode: "truncate",
      });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  // ─── fs_read ────────────────────────────────────────────────────────

  describe("fs_read", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("fs_read", {
        path: "/etc/hosts",
        encoding: "utf-8",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts valid args with only required fields", () => {
      const result = validator.validate("fs_read", { path: "/etc/hosts" });
      expect(result.valid).toBe(true);
    });

    it("rejects missing path", () => {
      const result = validator.validate("fs_read", { encoding: "utf-8" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects empty string path", () => {
      const result = validator.validate("fs_read", { path: "" });
      expect(result.valid).toBe(false);
    });
  });

  // ─── browser ────────────────────────────────────────────────────────

  describe("browser", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("browser", {
        url: "https://example.com",
        action: "navigate",
        data: { key: "value" },
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts empty object (all fields optional)", () => {
      const result = validator.validate("browser", {});
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts with only url", () => {
      const result = validator.validate("browser", { url: "https://example.com" });
      expect(result.valid).toBe(true);
    });

    it("accepts with only action", () => {
      const result = validator.validate("browser", { action: "click" });
      expect(result.valid).toBe(true);
    });
  });

  // ─── send ───────────────────────────────────────────────────────────

  describe("send", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("send", {
        destination: "https://api.example.com/data",
        payload: { message: "hello" },
        method: "POST",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts valid args with only required fields", () => {
      const result = validator.validate("send", {
        destination: "https://api.example.com",
      });
      expect(result.valid).toBe(true);
    });

    it("rejects missing destination", () => {
      const result = validator.validate("send", { payload: "data" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects empty string destination", () => {
      const result = validator.validate("send", { destination: "" });
      expect(result.valid).toBe(false);
    });
  });

  // ─── package ────────────────────────────────────────────────────────

  describe("package", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("package", {
        package_name: "lodash",
        version: "4.17.21",
        registry: "https://registry.npmjs.org",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts valid args with only required fields", () => {
      const result = validator.validate("package", { package_name: "zod" });
      expect(result.valid).toBe(true);
    });

    it("rejects missing package_name", () => {
      const result = validator.validate("package", { version: "1.0.0" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects empty string package_name", () => {
      const result = validator.validate("package", { package_name: "" });
      expect(result.valid).toBe(false);
    });
  });

  // ─── config ─────────────────────────────────────────────────────────

  describe("config", () => {
    it("accepts valid args with all fields", () => {
      const result = validator.validate("config", {
        key: "theme",
        value: "dark",
        scope: "user",
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it("accepts valid args with only required fields", () => {
      const result = validator.validate("config", { key: "theme", value: true });
      expect(result.valid).toBe(true);
    });

    it("accepts various value types (string, number, boolean, object)", () => {
      for (const value of ["str", 42, true, { nested: "obj" }]) {
        const result = validator.validate("config", { key: "k", value });
        expect(result.valid).toBe(true);
      }
    });

    it("rejects missing key", () => {
      const result = validator.validate("config", { value: "dark" });
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("rejects empty string key", () => {
      const result = validator.validate("config", { key: "", value: "v" });
      expect(result.valid).toBe(false);
    });
  });

  // ─── Extra fields (loose / passthrough) ─────────────────────────────

  describe("extra fields allowed (loose schemas)", () => {
    it("exec allows extra fields", () => {
      const result = validator.validate("exec", {
        command: "ls",
        timeout: 5000,
        custom_flag: true,
      });
      expect(result.valid).toBe(true);
    });

    it("fs_write allows extra fields", () => {
      const result = validator.validate("fs_write", {
        path: "/tmp/f",
        permissions: "0644",
      });
      expect(result.valid).toBe(true);
    });

    it("fs_read allows extra fields", () => {
      const result = validator.validate("fs_read", {
        path: "/tmp/f",
        follow_symlinks: true,
      });
      expect(result.valid).toBe(true);
    });

    it("browser allows extra fields", () => {
      const result = validator.validate("browser", {
        url: "https://example.com",
        viewport: { width: 1024, height: 768 },
      });
      expect(result.valid).toBe(true);
    });

    it("send allows extra fields", () => {
      const result = validator.validate("send", {
        destination: "https://api.example.com",
        headers: { Authorization: "Bearer token" },
      });
      expect(result.valid).toBe(true);
    });

    it("package allows extra fields", () => {
      const result = validator.validate("package", {
        package_name: "zod",
        dev: true,
      });
      expect(result.valid).toBe(true);
    });

    it("config allows extra fields", () => {
      const result = validator.validate("config", {
        key: "k",
        value: "v",
        metadata: { source: "cli" },
      });
      expect(result.valid).toBe(true);
    });
  });

  // ─── Type mismatches ────────────────────────────────────────────────

  describe("type mismatches", () => {
    it("rejects number instead of string for exec command", () => {
      const result = validator.validate("exec", { command: 123 });
      expect(result.valid).toBe(false);
    });

    it("rejects boolean instead of string for fs_write path", () => {
      const result = validator.validate("fs_write", { path: true });
      expect(result.valid).toBe(false);
    });

    it("rejects number instead of string for fs_read path", () => {
      const result = validator.validate("fs_read", { path: 999 });
      expect(result.valid).toBe(false);
    });

    it("rejects number instead of string for send destination", () => {
      const result = validator.validate("send", { destination: 42 });
      expect(result.valid).toBe(false);
    });

    it("rejects array instead of string for package_name", () => {
      const result = validator.validate("package", { package_name: ["zod"] });
      expect(result.valid).toBe(false);
    });

    it("rejects null instead of string for config key", () => {
      const result = validator.validate("config", { key: null, value: "v" });
      expect(result.valid).toBe(false);
    });
  });

  // ─── Empty parameters where required fields exist ───────────────────

  describe("empty parameters object", () => {
    it("rejects empty object for exec (command required)", () => {
      const result = validator.validate("exec", {});
      expect(result.valid).toBe(false);
    });

    it("rejects empty object for fs_write (path required)", () => {
      const result = validator.validate("fs_write", {});
      expect(result.valid).toBe(false);
    });

    it("rejects empty object for fs_read (path required)", () => {
      const result = validator.validate("fs_read", {});
      expect(result.valid).toBe(false);
    });

    it("rejects empty object for send (destination required)", () => {
      const result = validator.validate("send", {});
      expect(result.valid).toBe(false);
    });

    it("rejects empty object for package (package_name required)", () => {
      const result = validator.validate("package", {});
      expect(result.valid).toBe(false);
    });

    it("rejects empty object for config (key required)", () => {
      const result = validator.validate("config", {});
      expect(result.valid).toBe(false);
    });
  });

  // ─── Unknown category ───────────────────────────────────────────────

  describe("unknown category", () => {
    it("returns invalid for an unknown category name", () => {
      const result = validator.validate("nonexistent" as ToolCategoryName, {
        foo: "bar",
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('No argument schema for category "nonexistent"');
    });
  });

  // ─── Result immutability ────────────────────────────────────────────

  describe("result immutability", () => {
    it("returns frozen result for valid input", () => {
      const result = validator.validate("exec", { command: "ls" });
      expect(Object.isFrozen(result)).toBe(true);
    });

    it("returns frozen result for invalid input", () => {
      const result = validator.validate("exec", {});
      expect(Object.isFrozen(result)).toBe(true);
    });
  });
});
