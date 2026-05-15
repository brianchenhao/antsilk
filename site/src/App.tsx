import Hero from './components/Hero'
import Install from './components/Install'
import AttackCounter from './components/AttackCounter'
import HowItWorks from './components/HowItWorks'
import Footer from './components/Footer'

export default function App() {
  return (
    <div className="min-h-full">
      <main className="mx-auto max-w-5xl px-6 pt-16 pb-24 sm:pt-24">
        <Hero />
        <Install />
        <AttackCounter />
        <HowItWorks />
      </main>
      <Footer />
    </div>
  )
}
