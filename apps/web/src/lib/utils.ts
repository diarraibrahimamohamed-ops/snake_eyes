import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)); }
export const SEV: Record<string,{text:string,bg:string,border:string,hex:string}> = {
  critical:{text:"text-red-400",bg:"bg-red-400/10",border:"border-red-400/30",hex:"#ef4444"},
  high:{text:"text-orange-400",bg:"bg-orange-400/10",border:"border-orange-400/30",hex:"#f97316"},
  medium:{text:"text-yellow-400",bg:"bg-yellow-400/10",border:"border-yellow-400/30",hex:"#eab308"},
  low:{text:"text-green-400",bg:"bg-green-400/10",border:"border-green-400/30",hex:"#22c55e"},
  info:{text:"text-blue-400",bg:"bg-blue-400/10",border:"border-blue-400/30",hex:"#3b82f6"},
};
export const IOC_COLORS: Record<string,string> = {
  ip:"text-cyan-400",domain:"text-orange-400",url:"text-red-400",
  md5:"text-purple-400",sha256:"text-purple-500",cve:"text-red-500",email:"text-yellow-400",
};
export function formatRelative(d: string|Date): string {
  const diff = Math.floor((Date.now()-new Date(d).getTime())/1000);
  if(diff<60) return `${diff}s`;
  if(diff<3600) return `${Math.floor(diff/60)}m`;
  if(diff<86400) return `${Math.floor(diff/3600)}h`;
  return `${Math.floor(diff/86400)}j`;
}
