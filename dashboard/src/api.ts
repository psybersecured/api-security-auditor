import type { Finding, Operation, Overview, Project, Scan } from './types';

export const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const res = await fetch(`${API}${path}`, {headers:{'Content-Type':'application/json', ...(init?.headers||{})}, ...init});
  if(!res.ok){ const text = await res.text(); throw new Error(text || `${res.status} ${res.statusText}`); }
  if(res.status===204) return undefined as T;
  return res.json();
}
export const api = {
  overview:()=>request<Overview>('/api/overview'),
  projects:()=>request<Project[]>('/api/projects'),
  project:(id:number)=>request<Project>(`/api/projects/${id}`),
  operations:(id:number)=>request<Operation[]>(`/api/projects/${id}/operations`),
  createProject:(data:{name:string;description:string;spec_text:string})=>request<Project>('/api/projects',{method:'POST',body:JSON.stringify(data)}),
  scans:()=>request<Scan[]>('/api/scans'),
  scan:(id:number)=>request<Scan>(`/api/scans/${id}`),
  createScan:(data:any)=>request<Scan>('/api/scans',{method:'POST',body:JSON.stringify(data)}),
  findings:(scanId:number)=>request<Finding[]>(`/api/scans/${scanId}/findings`),
  allFindings:(severity?:string)=>request<Finding[]>(`/api/findings${severity?`?severity=${severity}`:''}`),
  reportHtml:(scanId:number)=>`${API}/api/reports/${scanId}.html`,
  reportJson:(scanId:number)=>`${API}/api/reports/${scanId}.json`,
};
