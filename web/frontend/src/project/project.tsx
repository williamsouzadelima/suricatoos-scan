import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

export type Project = { id: number; name: string; slug: string }
type Ctx = { projects: Project[]; currentSlug: string; setCurrentSlug: (s: string) => void }
const ProjectCtx = createContext<Ctx | null>(null)

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { data: projects = [] } = useQuery({
    queryKey: ['projects'],
    queryFn: async () => (await api.get<Project[]>('/projects/')).data,
  })
  const [currentSlug, setSlug] = useState<string>(() => localStorage.getItem('sx_project') || '')

  useEffect(() => {
    if (!currentSlug && projects.length) {
      setSlug(projects[0].slug)
      localStorage.setItem('sx_project', projects[0].slug)
    }
  }, [projects, currentSlug])

  function setCurrentSlug(s: string) { setSlug(s); localStorage.setItem('sx_project', s) }
  return <ProjectCtx.Provider value={{ projects, currentSlug, setCurrentSlug }}>{children}</ProjectCtx.Provider>
}

export function useProject() {
  const c = useContext(ProjectCtx)
  if (!c) throw new Error('useProject must be used within ProjectProvider')
  return c
}
