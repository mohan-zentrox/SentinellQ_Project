import { create } from "zustand";
import { api } from "../api/client";
import type { AlertListResponse, AlertOut } from "../api/types";

interface AlertsState {
  items: AlertOut[];
  total: number;
  isLoading: boolean;
  error: string | null;
  fetchAlerts: () => Promise<void>;
}

export const useAlertsStore = create<AlertsState>((set) => ({
  items: [],
  total: 0,
  isLoading: false,
  error: null,
  fetchAlerts: async () => {
    set({ isLoading: true, error: null });
    try {
      const data = await api.get<AlertListResponse>("/alerts?page=1&pageSize=50");
      set({ items: data.items, total: data.total, isLoading: false });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Failed to load alerts", isLoading: false });
    }
  },
}));
