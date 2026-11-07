import { Accordion, Text } from '@mantine/core'
import { faqs } from '@/content/faq'
import { Fact } from '@/components/Fact'
import { BookBand, PageHeader, Section, useHead } from '@/components/Page'

export function Faq() {
  useHead('Questions and answers', 'Common questions about life, critical illness and disability insurance.')
  return (
    <>
      <PageHeader eyebrow="FAQ" title="Questions and answers" lead="Plain answers to the questions people ask most." />
      <Section>
        <Accordion variant="separated" radius="md" maw={820} chevronPosition="right" multiple>
          {faqs.map((f) => (
            <Accordion.Item key={f.question} value={f.question}>
              <Accordion.Control>
                <Text fw={600}>{f.question}</Text>
              </Accordion.Control>
              <Accordion.Panel>
                {f.answer.map((p) => (
                  <Text key={p} lh={1.7} mb="xs">
                    {p}
                  </Text>
                ))}
                {f.fact && (
                  <Text lh={1.7}>
                    {f.fact === 'provinces' ? (
                      <>
                        We can advise residents of: <Fact field="provinces">{(p) => p.join(', ')}</Fact>.
                      </>
                    ) : (
                      <Fact field={f.fact} />
                    )}
                  </Text>
                )}
              </Accordion.Panel>
            </Accordion.Item>
          ))}
        </Accordion>
      </Section>
      <BookBand title="Still have a question?" text="Ask it in a consultation — there’s no such thing as a silly question about insurance." />
    </>
  )
}
