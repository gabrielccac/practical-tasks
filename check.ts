// src/eproc/session.ts
import { spawn } from "node:child_process";
import * as cheerio from "cheerio";

export interface EprocPythonSessionResult {
  phpsessid: string;
  page_source_html: string;
}

export interface ParsedSessionEndpoints {
  endpointEntries: Array<{
    label: string;
    endpoint: string;
    quantity: number | null;
  }>;
  processesEndpoints: string[];
  dueTodayEndpoint?: string;
  reportsEndpoint?: string;
}

function normalizeHref(href: string): string {
  return (href || "").replace(/&amp;/g, "&").trim();
}

function getActionFromEndpoint(endpoint: string): string {
  const query = endpoint.includes("?") ? endpoint.split("?")[1] : "";
  const params = new URLSearchParams(query);
  return (params.get("acao") || "").trim();
}

function isUrgentEndpoint(endpoint: string): boolean {
  const query = endpoint.includes("?") ? endpoint.split("?")[1] : "";
  const params = new URLSearchParams(query);
  return params.get("urgente") === "true" || getActionFromEndpoint(endpoint).endsWith("_urgente");
}

export function parseEndpoints(pageHtml: string): ParsedSessionEndpoints {
  const $ = cheerio.load(pageHtml);
  const endpointEntries: ParsedSessionEndpoints["endpointEntries"] = [];
  const processEndpointSet = new Set<string>();

  $("table.infraTable tbody tr").each((_, row) => {
    const label = ($(row).find("td").first().text() || "").replace(/\s+/g, " ").trim();
    const href = normalizeHref($(row).find("td a[href]").first().attr("href") || "");
    const quantityText = ($(row).find("td a[href]").first().text() || "").trim();
    const parsedQuantity = Number.parseInt(quantityText, 10);
    const quantity = Number.isFinite(parsedQuantity) ? parsedQuantity : null;

    if (!label || !href) {
      return;
    }

    endpointEntries.push({ label, endpoint: href, quantity });
  });

  for (const entry of endpointEntries) {
    const action = getActionFromEndpoint(entry.endpoint);
    const allowedAction =
      action === "citacao_intimacao_prazo_aberto_listar"
      || action === "citacao_intimacao_pendente_listar";

    if (!allowedAction || isUrgentEndpoint(entry.endpoint)) {
      continue;
    }

    processEndpointSet.add(entry.endpoint);
  }

  return {
    endpointEntries,
    processesEndpoints: [...processEndpointSet],
  };
}