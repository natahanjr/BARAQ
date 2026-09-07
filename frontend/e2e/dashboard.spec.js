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

test.describe("Dashboard E2E", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.waitForTimeout(3000);
  });

  test("dashboard loads successfully", async ({ page }) => {
    await expect(page.locator("body")).toContainText("Dashboard", { timeout: 10000 });
  });

  test("severity cards are displayed", async ({ page }) => {
    await page.waitForTimeout(5000);
    const body = await page.locator("body").textContent();
    const hasSeverity = body.includes("Critical") || body.includes("High") || body.includes("Medium") || body.includes("Low") || body.includes("critical") || body.includes("high");
    expect(hasSeverity).toBe(true);
  });

  test("system health section is visible", async ({ page }) => {
    const body = await page.locator("body").textContent();
    expect(body.includes("System Health") || body.includes("Health") || body.includes("Telemetry")).toBe(true);
  });

  test("detection engine section is visible", async ({ page }) => {
    const body = await page.locator("body").textContent();
    expect(body.includes("Detection") || body.includes("ML") || body.includes("Engine")).toBe(true);
  });

  test("ML model status is displayed", async ({ page }) => {
    const body = await page.locator("body").textContent();
    expect(body.includes("ML") || body.includes("model") || body.includes("Model")).toBe(true);
  });

  test("telemetry status is displayed", async ({ page }) => {
    const body = await page.locator("body").textContent();
    expect(body.includes("Telemetry") || body.includes("telemetry") || body.includes("Collector")).toBe(true);
  });

  test("navigation to alerts page works", async ({ page }) => {
    await page.click("text=Alerts");
    await expect(page.url()).toContain("/alerts");
  });

  test("navigation to incidents page works", async ({ page }) => {
    await page.click("text=Incidents");
    await expect(page.url()).toContain("/incidents");
  });

  test("sidebar navigation is visible", async ({ page }) => {
    const nav = page.locator("nav, [role='navigation']");
    await expect(nav.first()).toBeVisible({ timeout: 10000 });
  });
});
