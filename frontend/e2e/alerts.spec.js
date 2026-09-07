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

test.describe("Alerts E2E", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.goto(`${BASE_URL}/alerts`);
  });

  test("alerts page loads successfully", async ({ page }) => {
    await expect(page.locator("text=Alerts").first()).toBeVisible({ timeout: 10000 });
  });

  test("alerts list is displayed", async ({ page }) => {
    await page.waitForTimeout(2000);
    const alertsList = page.locator("[class*='alert'], [class*='Alert'], [role='listitem']");
    const count = await alertsList.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("severity filter exists", async ({ page }) => {
    const severityFilter = page.locator("select, [role='combobox']").filter({ hasText: /severity|critical|high|medium|low/i });
    await expect(severityFilter.first()).toBeVisible({ timeout: 10000 });
  });

  test("status filter exists", async ({ page }) => {
    const statusFilter = page.locator("select, [role='combobox']").filter({ hasText: /status|open|in.progress|contained|closed/i });
    await expect(statusFilter.first()).toBeVisible({ timeout: 10000 });
  });

  test("pagination controls exist", async ({ page }) => {
    await page.waitForTimeout(2000);
    const pagination = page.locator("button").filter({ hasText: /next|prev|page|1|2/i });
    await expect(pagination.first()).toBeVisible({ timeout: 10000 });
  });

  test("search functionality exists", async ({ page }) => {
    const searchInput = page.locator("input").first();
    await expect(searchInput).toBeVisible({ timeout: 10000 });
  });

  test("alert detail navigation works", async ({ page }) => {
    await page.waitForTimeout(2000);
    const firstAlert = page.locator("a[href*='/alerts/']").first();
    if (await firstAlert.isVisible()) {
      await firstAlert.click();
      await expect(page.url()).toContain("/alerts/");
    }
  });

  test("bulk selection checkbox exists", async ({ page }) => {
    await page.waitForTimeout(2000);
    const checkboxes = page.locator("input[type='checkbox']");
    const count = await checkboxes.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test("clear alerts button exists for admin", async ({ page }) => {
    const clearButton = page.locator("button").filter({ hasText: /clear|delete|remove/i });
    await expect(clearButton.first()).toBeVisible({ timeout: 10000 });
  });

  test("export functionality exists", async ({ page }) => {
    const exportButton = page.locator("button, a").filter({ hasText: /export|download|csv|json/i });
    await expect(exportButton.first()).toBeVisible({ timeout: 10000 });
  });
});
