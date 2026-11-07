import { lazy, Suspense } from 'react'
import { Route, Routes } from 'react-router-dom'
import { Center, Loader } from '@mantine/core'
import { services } from '@/content/services'
import { Layout } from '@/components/Layout'
import { Home } from '@/pages/Home'
import { ServicePage } from '@/pages/ServicePage'
import { About } from '@/pages/About'
import { Faq } from '@/pages/Faq'
import { Book } from '@/pages/Book'
import { Account } from '@/pages/Account'
import { SignInLink } from '@/pages/SignInLink'
import { Accessibility, Disclosure, NotFound, Privacy, Terms } from '@/pages/Legal'

// The dashboard is its own download: visitors never load it.
const AdminApp = lazy(() => import('@/admin/AdminApp'))

export function App() {
  return (
    <Routes>
      <Route
        path="/admin/*"
        element={
          <Suspense
            fallback={
              <Center mih="60vh">
                <Loader />
              </Center>
            }
          >
            <AdminApp />
          </Suspense>
        }
      />
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        {services.map((s) => (
          <Route key={s.slug} path={s.slug} element={<ServicePage service={s} />} />
        ))}
        <Route path="about" element={<About />} />
        <Route path="faq" element={<Faq />} />
        <Route path="book" element={<Book />} />
        <Route path="account" element={<Account />} />
        <Route path="sign-in/link" element={<SignInLink />} />
        <Route path="disclosure" element={<Disclosure />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="terms" element={<Terms />} />
        <Route path="accessibility" element={<Accessibility />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
