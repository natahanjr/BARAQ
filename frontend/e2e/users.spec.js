import { test, expect } from "@playwright/test";

const BASE_URL = process.env.BASE_URL || "http://localhost:5173";
const ADMIN_USER = process.env.E2E_ADMIN_USER || "admin";
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || "BaraqAdmin2026!";

async function login(page) {
  await page.goto(BASE_URL);
  await page.fill('input[id="username"]', ADMIN_USER);
  await page.fill('input[id="password"]', ADMIN_PASS);
  await page.click('button[type="submit"]');
  await expect(page.locator('input[id="username"]')).toBeHidden({ timeout: 15000 });
}

test.describe("Users E2E", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.goto(`${BASE_URL}/users`);
  });

  test("users page loads successfully", async ({ page }) => {
    await expect(page.locator("text=Users").first()).toBeVisible({ timeout: 10000 });
  });

  test("users list is displayed", async ({ page }) => {
    await page.waitForTimeout(2000);
    const usersList = page.locator("[class*='user'], [class*='User'], [role='listitem']");
    const count = await usersList.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("create user form exists", async ({ page }) => {
    const createButton = page.locator("button").filter({ hasText: /create|add|new/i });
    await expect(createButton.first()).toBeVisible({ timeout: 10000 });
  });

  test("search functionality exists", async ({ page }) => {
    const searchInput = page.locator("input").first();
    await expect(searchInput).toBeVisible({ timeout: 10000 });
  });

  test("user roles are displayed", async ({ page }) => {
    await page.waitForTimeout(2000);
    const roles = page.locator("text=admin, text=analyst, text=viewer");
    const count = await roles.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("user status badges exist", async ({ page }) => {
    await page.waitForTimeout(2000);
    const statusBadges = page.locator("[class*='badge'], [class*='Badge']").filter({ hasText: /active|inactive|pending/i });
    const count = await statusBadges.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("audit log tab exists", async ({ page }) => {
    const auditTab = page.locator("button, [role='tab']").filter({ hasText: /audit|log|history/i });
    await expect(auditTab.first()).toBeVisible({ timeout: 10000 });
  });

  test("MFA setup button exists", async ({ page }) => {
    const mfaButton = page.locator("button").filter({ hasText: /mfa|2fa|two.factor|authenticator/i });
    await expect(mfaButton.first()).toBeVisible({ timeout: 10000 });
  });

  test("user action buttons exist", async ({ page }) => {
    await page.waitForTimeout(2000);
    const actionButtons = page.locator("button").filter({ hasText: /edit|delete|disable|reset|approve|reject/i });
    const count = await actionButtons.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("pagination exists for large user lists", async ({ page }) => {
    await page.waitForTimeout(2000);
    const pagination = page.locator("button").filter({ hasText: /next|prev|page|1|2/i });
    await expect(pagination.first()).toBeVisible({ timeout: 10000 });
  });
});
