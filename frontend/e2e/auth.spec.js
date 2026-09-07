import { test, expect } from "@playwright/test";

const BASE_URL = process.env.BASE_URL || "http://localhost:5173";
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "BaraqAdmin2026!";
const TEST_USER = process.env.E2E_TEST_USER || "testuser";
const TEST_PASS = process.env.E2E_TEST_PASS || "testpassword123";

test.describe("Authentication E2E", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
  });

  test("login page renders correctly", async ({ page }) => {
    await expect(page.locator("h1")).toContainText("BARAQ");
    await expect(page.locator('input[id="username"]')).toBeVisible();
    await expect(page.locator('input[id="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toContainText("Sign In");
  });

  test("default credentials hint is displayed", async ({ page }) => {
    await expect(page.locator("text=Default account:")).toBeVisible();
  });

  test("register link navigates to registration mode", async ({ page }) => {
    await page.click("text=New here? Create an account");
    await expect(page.locator('input[id="reg-username"]')).toBeVisible();
    await expect(page.locator('input[id="reg-password"]')).toBeVisible();
    await expect(page.locator('input[id="reg-confirm"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toContainText("Create Account");
  });
});
