"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import { LayoutDashboard, Database, Globe, AlertTriangle, Radio, Bug, Settings, LogOut, Shield, User, Crosshair } from "lucide-react";
import { useAuthStore } from "@/lib/stores/auth";
import { cn } from "@/lib/utils";

const NAV = [
  {href:"/dashboard",icon:LayoutDashboard,label:"Dashboard"},
  {href:"/threat-intel/iocs",icon:Database,label:"Threat Intel"},
  {href:"/osint",icon:Globe,label:"OSINT"},
  {href:"/soc/alerts",icon:AlertTriangle,label:"SOC Alerts"},
  {href:"/soc/incidents",icon:Radio,label:"Incidents"},
  {href:"/vulns",icon:Bug,label:"Vulnérabilités"},
  {href:"/offensive-lab",icon:Crosshair,label:"Offensive Lab"},
  {href:"/security-lab",icon:Shield,label:"Security Lab"},
  {href:"/settings",icon:Settings,label:"Paramètres"},
];

export function Sidebar() {
  const pathname = usePathname();
  const { logout } = useAuthStore();
  return (
    <aside className="w-14 flex-shrink-0 bg-[#07101f] border-r border-cyan-900/30 flex flex-col items-center py-4 gap-2">
      <div className="mb-4"><Shield className="w-7 h-7 text-cyan-400"/></div>
      <nav className="flex-1 flex flex-col gap-1 w-full px-2">
        {NAV.map(item=>{
          const active = pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link key={item.href} href={item.href}>
              <div className={cn("relative flex items-center justify-center w-10 h-10 rounded-sm transition-all duration-200 group",
                active ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30" : "text-gray-500 hover:text-cyan-400 hover:bg-cyan-900/20")}>
                <Icon className="w-4 h-4"/>
                {active && <motion.div layoutId="activeBar" className="absolute right-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-cyan-400 rounded-full"/>}
                <div className="absolute left-12 bg-[#0a1628] border border-cyan-900/50 text-cyan-300 text-[10px] tracking-widest px-2 py-1 rounded-sm whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none z-50 transition-opacity">{item.label}</div>
              </div>
            </Link>
          );
        })}
      </nav>
      <div className="flex flex-col items-center gap-2">
        <div className="w-8 h-8 rounded-full bg-cyan-900/30 border border-cyan-700/30 flex items-center justify-center">
          <User className="w-4 h-4 text-cyan-500"/>
        </div>
        <button onClick={logout} className="text-gray-600 hover:text-red-400 transition-colors" title="Déconnexion">
          <LogOut className="w-4 h-4"/>
        </button>
      </div>
    </aside>
  );
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden bg-[#060d1a]">
      <Sidebar/>
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  );
}
