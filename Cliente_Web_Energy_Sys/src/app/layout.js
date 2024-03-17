import { Inter } from "next/font/google";
import "../styles/globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata = {
  title: "Energy System",
  description: "Sistema de monitoreo de energia electrica en el hogar",
};

export default function RootLayout({ children }) {

  return (
    <html lang="en">
      <body className={inter.className}>
      <div className="dark:bg-boxdark-2 dark:text-bodydark">
        </div>
      </body>
    </html>
  );
}
