/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#eef6ff",
          100: "#d9ecff",
          500: "#2f6fed",
          600: "#2358c2",
          700: "#1c469a",
          900: "#0f2554",
        },
        severity: {
          informational: "#64748b",
          low: "#3b82f6",
          medium: "#eab308",
          high: "#f97316",
          critical: "#dc2626",
        },
      },
    },
  },
  plugins: [],
};
