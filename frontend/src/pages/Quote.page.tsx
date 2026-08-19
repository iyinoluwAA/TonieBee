import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Stepper,
  Button,
  Group,
  TextInput,
  Select,
  Textarea,
  NumberInput,
  Paper,
  Title,
  Text,
  Stack,
  Radio,
  Box,
  Card,
  ThemeIcon,
  rem,
  Alert,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import {
  IconShield,
  IconHeart,
  IconTrendingUp,
  IconCheck,
  IconInfoCircle,
} from '@tabler/icons-react';
import { useForm } from '@mantine/form';
import { Navbar } from '../components/Navigation';
import { notifications } from '@mantine/notifications';

const serviceTypes = [
  { value: 'life', label: 'Life Insurance', icon: IconShield, color: 'trustBlue' },
  { value: 'critical_illness', label: 'Critical Illness', icon: IconHeart, color: 'calmingTeal' },
  { value: 'disability', label: 'Disability Insurance', icon: IconTrendingUp, color: 'warmOrange' },
  { value: 'combined', label: 'Combined Coverage', icon: IconShield, color: 'trustBlue' },
];

export function QuotePage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [active, setActive] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const form = useForm({
    initialValues: {
      service_type: '',
      coverage_amount: '',
      coverage_term: '',
      first_name: '',
      last_name: '',
      email: '',
      phone: '',
      date_of_birth: '',
      address: '',
      city: '',
      province: '',
      postal_code: '',
      occupation: '',
      annual_income: '',
      smoker: '',
      health_conditions: '',
      medications: '',
      additional_info: '',
    },
    validate: {
      service_type: (value) => (!value ? 'Please select a service type' : null),
      first_name: (value) => {
        if (!value) return 'First name is required';
        if (value.length < 2) return 'First name must be at least 2 characters';
        if (value.length > 50) return 'First name must be less than 50 characters';
        if (!/^[a-zA-Z\s\-'\.]+$/.test(value)) return 'First name contains invalid characters';
        return null;
      },
      last_name: (value) => {
        if (!value) return 'Last name is required';
        if (value.length < 2) return 'Last name must be at least 2 characters';
        if (value.length > 50) return 'Last name must be less than 50 characters';
        if (!/^[a-zA-Z\s\-'\.]+$/.test(value)) return 'Last name contains invalid characters';
        return null;
      },
      email: (value) => {
        if (!value) return 'Email is required';
        if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'Invalid email format';
        if (value.length > 255) return 'Email is too long';
        return null;
      },
      phone: (value) => {
        if (!value) return 'Phone number is required';
        const cleaned = value.replace(/[\s\(\)\-\+\.]/g, '');
        if (cleaned.length < 10 || cleaned.length > 15) return 'Phone number must be between 10 and 15 digits';
        if (!/^\d+$/.test(cleaned)) return 'Phone number contains invalid characters';
        return null;
      },
      date_of_birth: (value) => {
        if (!value) return 'Date of birth is required';
        const date = new Date(value);
        const today = new Date();
        const age = today.getFullYear() - date.getFullYear();
        const monthDiff = today.getMonth() - date.getMonth();
        const actualAge = monthDiff < 0 || (monthDiff === 0 && today.getDate() < date.getDate()) ? age - 1 : age;
        if (actualAge < 18) return 'You must be at least 18 years old';
        if (actualAge > 100) return 'Please verify your date of birth';
        return null;
      },
      address: (value) => (!value ? 'Address is required' : null),
      city: (value) => (!value ? 'City is required' : null),
      province: (value) => (!value ? 'Province is required' : null),
      postal_code: (value) => {
        if (!value) return 'Postal code is required';
        const cleaned = value.replace(/\s/g, '').toUpperCase();
        if (!/^[A-Z]\d[A-Z][ -]?\d[A-Z]\d$/.test(cleaned)) return 'Invalid Canadian postal code format (e.g., M5H 2N2)';
        return null;
      },
      coverage_amount: (value) => {
        if (!value) return 'Coverage amount is required';
        const amount = parseFloat(value.replace(/[^0-9.]/g, ''));
        if (isNaN(amount)) return 'Invalid amount';
        if (amount < 10000) return 'Coverage amount must be at least $10,000';
        if (amount > 10000000) return 'Coverage amount cannot exceed $10,000,000';
        return null;
      },
      coverage_term: (value) => {
        if (value) {
          const term = parseInt(value);
          if (isNaN(term) || term < 1) return 'Term must be at least 1 year';
          if (term > 50) return 'Term cannot exceed 50 years';
        }
        return null;
      },
    },
  });

  // Save form progress to localStorage
  const saveProgress = () => {
    try {
      localStorage.setItem('quote_form_progress', JSON.stringify(form.values));
    } catch (e) {
      // Ignore localStorage errors
    }
  };

  // Load form progress from localStorage
  const loadProgress = () => {
    try {
      const saved = localStorage.getItem('quote_form_progress');
      if (saved) {
        const savedValues = JSON.parse(saved);
        form.setValues(savedValues);
      }
    } catch (e) {
      // Ignore localStorage errors
    }
  };

  // Load progress on mount
  useEffect(() => {
    loadProgress();
  }, []);

  // Auto-save progress on field changes (debounced)
  useEffect(() => {
    const timer = setTimeout(() => {
      saveProgress();
    }, 1000); // Save 1 second after last change
    return () => clearTimeout(timer);
  }, [form.values]);

  const nextStep = () => {
    // Step 1: Service Selection
    if (active === 0) {
      form.validateField('service_type');
      if (!form.values.service_type || form.errors.service_type) return;
    }
    // Step 2: Personal Information
    else if (active === 1) {
      form.validateField('first_name');
      form.validateField('last_name');
      form.validateField('email');
      form.validateField('phone');
      form.validateField('date_of_birth');
      if (form.errors.first_name || form.errors.last_name || form.errors.email || form.errors.phone || form.errors.date_of_birth) return;
    }
    // Step 3: Coverage Needs
    else if (active === 2) {
      form.validateField('coverage_amount');
      form.validateField('coverage_term');
      if (form.errors.coverage_amount || form.errors.coverage_term) return;
    }
    // Step 4: Health & Lifestyle
    else if (active === 3) {
      // No required fields, can proceed
    }
    // Step 5: Financial Information
    else if (active === 4) {
      form.validateField('address');
      form.validateField('city');
      form.validateField('province');
      form.validateField('postal_code');
      if (form.errors.address || form.errors.city || form.errors.province || form.errors.postal_code) return;
    }
    // Step 6: Review (no validation needed)
    
    saveProgress(); // Save progress before moving to next step
    setActive((current) => (current < 5 ? current + 1 : current));
  };

  const prevStep = () => setActive((current) => (current > 0 ? current - 1 : current));

  const handleSubmit = async () => {
    setError(null);
    setLoading(true);

    try {
      const personal_info = {
        first_name: form.values.first_name,
        last_name: form.values.last_name,
        email: form.values.email,
        phone: form.values.phone,
        date_of_birth: form.values.date_of_birth,
        address: form.values.address,
        city: form.values.city,
        province: form.values.province,
        postal_code: form.values.postal_code,
        occupation: form.values.occupation,
        annual_income: form.values.annual_income,
      };

      const health_info = {
        smoker: form.values.smoker,
        health_conditions: form.values.health_conditions,
        medications: form.values.medications,
      };

      const response = await fetch('/api/quotes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          service_type: form.values.service_type,
          coverage_amount: form.values.coverage_amount ? parseFloat(form.values.coverage_amount) : null,
          coverage_term: form.values.coverage_term ? parseInt(form.values.coverage_term) : null,
          personal_info,
          health_info: form.values.smoker || form.values.health_conditions || form.values.medications ? health_info : null,
          additional_info: form.values.additional_info || null,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success') {
          // Clear saved progress
          try {
            localStorage.removeItem('quote_form_progress');
          } catch (e) {
            // Ignore
          }
          setSuccess(true);
          notifications.show({
            title: 'Quote Request Submitted!',
            message: 'Our team will review your request and get back to you within 24-48 hours.',
            color: 'green',
            autoClose: 5000,
          });
          setTimeout(() => {
            navigate('/profile');
          }, 3000);
        }
      } else {
        const error = await response.json().catch(() => ({ message: 'Failed to submit quote request' }));
        const errorMessage = error.message || 'Failed to submit quote request. Please try again.';
        
        // Handle rate limiting specifically
        if (errorMessage.includes('Rate limit')) {
          notifications.show({
            title: 'Rate Limit Exceeded',
            message: errorMessage,
            color: 'orange',
            autoClose: 10000,
          });
        }
        
        setError(errorMessage);
      }
    } catch (err: any) {
      setError('Failed to submit quote request. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <Box>
        <Navbar />
        <Container size="md" py={{ base: 'xl', sm: '5xl' }}>
          <Paper
            p={{ base: 'xl', sm: '3xl' }}
            radius="xl"
            style={{
              background: 'linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%)',
              textAlign: 'center',
            }}
          >
            <Stack gap="lg" align="center">
              <ThemeIcon size={80} radius="xl" color="white" variant="filled">
                <IconCheck size={40} />
              </ThemeIcon>
              <Title order={2} size={isMobile ? rem(28) : rem(36)} c="white">
                Quote Request Submitted!
              </Title>
              <Text size={isMobile ? 'sm' : 'md'} c="gray.1" maw={500}>
                Thank you for your interest. Our team will review your request and get back to you within 24-48 hours with a personalized quote.
              </Text>
              <Button
                size="lg"
                radius="xl"
                variant="white"
                color="dark"
                onClick={() => navigate('/profile')}
                mt="md"
              >
                Go to Dashboard
              </Button>
            </Stack>
          </Paper>
        </Container>
      </Box>
    );
  }

  return (
    <Box>
      <Navbar />
      <Container size="md" py={{ base: 'xl', sm: '5xl' }}>
        <Stack gap="xl">
          <Box ta="center">
            <Title order={1} size={isMobile ? rem(32) : rem(48)} mb="md" c="dark.9">
              Get Your Free Quote
            </Title>
            <Text size={isMobile ? 'sm' : 'md'} c="dark.7" maw={600} mx="auto">
              Fill out the form below and our team will provide you with a personalized insurance quote tailored to your needs.
            </Text>
          </Box>

          <Stepper
            active={active}
            onStepClick={setActive}
            breakpoint="sm"
            size={isMobile ? 'sm' : 'md'}
            styles={{
              stepBody: { marginTop: rem(8) },
              stepDescription: { marginTop: rem(4) },
            }}
          >
            <Stepper.Step label="Service Selection" description="Choose your coverage">
              <Paper p="xl" radius="lg" mt="xl" withBorder>
                <Stack gap="md">
                  <Text fw={600} size="lg" mb="sm">
                    What type of insurance are you looking for?
                  </Text>
                  <Radio.Group
                    {...form.getInputProps('service_type')}
                    error={form.errors.service_type}
                  >
                    <Stack gap="md" mt="xs">
                      {serviceTypes.map((service) => {
                        const Icon = service.icon;
                        return (
                          <Card
                            key={service.value}
                            p="md"
                            radius="md"
                            withBorder
                            style={{
                              cursor: 'pointer',
                              borderColor: form.values.service_type === service.value
                                ? `var(--mantine-color-${service.color}-6)`
                                : undefined,
                              borderWidth: form.values.service_type === service.value ? 2 : 1,
                              transition: 'all 0.2s ease',
                            }}
                            onClick={() => form.setFieldValue('service_type', service.value)}
                          >
                            <Group gap="md" wrap="nowrap">
                              <Radio value={service.value} />
                              <ThemeIcon size={40} radius="md" color={service.color} variant="light">
                                <Icon size={20} />
                              </ThemeIcon>
                              <Text fw={500}>{service.label}</Text>
                            </Group>
                          </Card>
                        );
                      })}
                    </Stack>
                  </Radio.Group>
                </Stack>
              </Paper>
            </Stepper.Step>

            <Stepper.Step label="Personal Information" description="Basic details">
              <Paper p="xl" radius="lg" mt="xl" withBorder>
                <Stack gap="md">
                  <Group grow>
                    <TextInput
                      label="First Name"
                      placeholder="John"
                      {...form.getInputProps('first_name')}
                      required
                      size="md"
                    />
                    <TextInput
                      label="Last Name"
                      placeholder="Doe"
                      {...form.getInputProps('last_name')}
                      required
                      size="md"
                    />
                  </Group>
                  <TextInput
                    label="Email"
                    placeholder="john.doe@example.com"
                    type="email"
                    {...form.getInputProps('email')}
                    required
                    size="md"
                  />
                  <TextInput
                    label="Phone"
                    placeholder="(555) 123-4567"
                    {...form.getInputProps('phone')}
                    required
                    size="md"
                  />
                  <TextInput
                    label="Date of Birth"
                    type="date"
                    {...form.getInputProps('date_of_birth')}
                    required
                    size="md"
                  />
                </Stack>
              </Paper>
            </Stepper.Step>

            <Stepper.Step label="Coverage Needs" description="Amount and term">
              <Paper p="xl" radius="lg" mt="xl" withBorder>
                <Stack gap="md">
                  <NumberInput
                    label="Coverage Amount (CAD)"
                    placeholder="e.g., 500000"
                    {...form.getInputProps('coverage_amount')}
                    min={0}
                    step={10000}
                    parser={(value) => value?.replace(/\$\s?|(,*)/g, '')}
                    formatter={(value) =>
                      !Number.isNaN(parseFloat(value || ''))
                        ? `$ ${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
                        : '$ '
                    }
                    size="md"
                    required
                  />
                  <NumberInput
                    label="Coverage Term (years)"
                    placeholder="e.g., 20"
                    {...form.getInputProps('coverage_term')}
                    min={1}
                    max={50}
                    size="md"
                  />
                  <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light" mt="md">
                    <Text size="sm">
                      Don't worry if you're unsure about these amounts. Our advisors will help you determine the right coverage for your needs.
                    </Text>
                  </Alert>
                </Stack>
              </Paper>
            </Stepper.Step>

            <Stepper.Step label="Health & Lifestyle" description="Health information">
              <Paper p="xl" radius="lg" mt="xl" withBorder>
                <Stack gap="md">
                  <TextInput
                    label="Occupation"
                    placeholder="Software Engineer"
                    {...form.getInputProps('occupation')}
                    size="md"
                  />
                  <Select
                    label="Are you a smoker?"
                    placeholder="Select an option"
                    data={['No', 'Yes', 'Occasionally']}
                    {...form.getInputProps('smoker')}
                    size="md"
                  />
                  <Textarea
                    label="Health Conditions"
                    placeholder="Please list any existing health conditions (optional)"
                    {...form.getInputProps('health_conditions')}
                    minRows={3}
                    size="md"
                  />
                  <Textarea
                    label="Current Medications"
                    placeholder="Please list any current medications (optional)"
                    {...form.getInputProps('medications')}
                    minRows={3}
                    size="md"
                  />
                </Stack>
              </Paper>
            </Stepper.Step>

            <Stepper.Step label="Financial & Address" description="Financial and location">
              <Paper p="xl" radius="lg" mt="xl" withBorder>
                <Stack gap="md">
                  <NumberInput
                    label="Annual Income (CAD)"
                    placeholder="e.g., 75000"
                    {...form.getInputProps('annual_income')}
                    min={0}
                    parser={(value) => value?.replace(/\$\s?|(,*)/g, '')}
                    formatter={(value) =>
                      !Number.isNaN(parseFloat(value || ''))
                        ? `$ ${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
                        : '$ '
                    }
                    size="md"
                  />
                  <TextInput
                    label="Address"
                    placeholder="123 Main Street"
                    {...form.getInputProps('address')}
                    required
                    size="md"
                  />
                  <Group grow>
                    <TextInput
                      label="City"
                      placeholder="Toronto"
                      {...form.getInputProps('city')}
                      required
                      size="md"
                    />
                    <Select
                      label="Province"
                      placeholder="Select province"
                      data={[
                        'Alberta',
                        'British Columbia',
                        'Manitoba',
                        'New Brunswick',
                        'Newfoundland and Labrador',
                        'Northwest Territories',
                        'Nova Scotia',
                        'Nunavut',
                        'Ontario',
                        'Prince Edward Island',
                        'Quebec',
                        'Saskatchewan',
                        'Yukon',
                      ]}
                      {...form.getInputProps('province')}
                      required
                      size="md"
                    />
                  </Group>
                  <TextInput
                    label="Postal Code"
                    placeholder="M5H 2N2"
                    {...form.getInputProps('postal_code')}
                    required
                    size="md"
                  />
                </Stack>
              </Paper>
            </Stepper.Step>

            <Stepper.Step label="Review & Submit" description="Review your information">
              <Paper p="xl" radius="lg" mt="xl" withBorder>
                <Stack gap="lg">
                  <Title order={3} size="h4" mb="md">
                    Review Your Quote Request
                  </Title>
                  
                  {/* Service Type */}
                  <Box>
                    <Text fw={600} size="sm" c="dimmed" mb={4} tt="uppercase">
                      Service Type
                    </Text>
                    <Text size="md" fw={500}>
                      {serviceTypes.find(s => s.value === form.values.service_type)?.label || 'Not selected'}
                    </Text>
                  </Box>

                  {/* Personal Info */}
                  <Box>
                    <Text fw={600} size="sm" c="dimmed" mb={4} tt="uppercase">
                      Personal Information
                    </Text>
                    <Text size="md" mb={2}>
                      <strong>Name:</strong> {form.values.first_name} {form.values.last_name}
                    </Text>
                    <Text size="md" mb={2}>
                      <strong>Email:</strong> {form.values.email}
                    </Text>
                    <Text size="md" mb={2}>
                      <strong>Phone:</strong> {form.values.phone}
                    </Text>
                    <Text size="md">
                      <strong>Date of Birth:</strong> {form.values.date_of_birth ? new Date(form.values.date_of_birth).toLocaleDateString() : 'Not provided'}
                    </Text>
                  </Box>

                  {/* Coverage */}
                  <Box>
                    <Text fw={600} size="sm" c="dimmed" mb={4} tt="uppercase">
                      Coverage Details
                    </Text>
                    <Text size="md" mb={2}>
                      <strong>Coverage Amount:</strong> {form.values.coverage_amount ? `$${parseFloat(form.values.coverage_amount.replace(/[^0-9.]/g, '')).toLocaleString()}` : 'Not specified'}
                    </Text>
                    {form.values.coverage_term && (
                      <Text size="md">
                        <strong>Term:</strong> {form.values.coverage_term} years
                      </Text>
                    )}
                  </Box>

                  {/* Address */}
                  <Box>
                    <Text fw={600} size="sm" c="dimmed" mb={4} tt="uppercase">
                      Address
                    </Text>
                    <Text size="md">
                      {form.values.address}, {form.values.city}, {form.values.province} {form.values.postal_code}
                    </Text>
                  </Box>

                  {/* Additional Info */}
                  {(form.values.occupation || form.values.smoker || form.values.health_conditions || form.values.medications || form.values.annual_income) && (
                    <Box>
                      <Text fw={600} size="sm" c="dimmed" mb={4} tt="uppercase">
                        Additional Information
                      </Text>
                      {form.values.occupation && (
                        <Text size="md" mb={2}>
                          <strong>Occupation:</strong> {form.values.occupation}
                        </Text>
                      )}
                      {form.values.annual_income && (
                        <Text size="md" mb={2}>
                          <strong>Annual Income:</strong> ${parseFloat(form.values.annual_income.replace(/[^0-9.]/g, '')).toLocaleString()}
                        </Text>
                      )}
                      {form.values.smoker && (
                        <Text size="md" mb={2}>
                          <strong>Smoking Status:</strong> {form.values.smoker}
                        </Text>
                      )}
                      {form.values.health_conditions && (
                        <Text size="md" mb={2}>
                          <strong>Health Conditions:</strong> {form.values.health_conditions}
                        </Text>
                      )}
                      {form.values.medications && (
                        <Text size="md">
                          <strong>Medications:</strong> {form.values.medications}
                        </Text>
                      )}
                    </Box>
                  )}

                  {form.values.additional_info && (
                    <Box>
                      <Text fw={600} size="sm" c="dimmed" mb={4} tt="uppercase">
                        Additional Notes
                      </Text>
                      <Text size="md">
                        {form.values.additional_info}
                      </Text>
                    </Box>
                  )}

                  <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light" mt="md">
                    <Text size="sm">
                      Please review all information carefully. Once submitted, our team will review your request and contact you within 24-48 hours.
                    </Text>
                  </Alert>
                </Stack>
              </Paper>
            </Stepper.Step>
          </Stepper>

          {error && (
            <Alert color="red" title="Error" onClose={() => setError(null)} withCloseButton>
              {error}
            </Alert>
          )}

          <Group justify="space-between" mt="xl">
            <Button
              variant="subtle"
              onClick={prevStep}
              disabled={active === 0}
              size={isMobile ? 'md' : 'lg'}
            >
              Back
            </Button>
            {active < 5 ? (
              <Button
                onClick={nextStep}
                size={isMobile ? 'md' : 'lg'}
                style={{
                  background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                  border: 'none',
                }}
              >
                Next Step
              </Button>
            ) : (
              <Button
                onClick={handleSubmit}
                loading={loading}
                size={isMobile ? 'md' : 'lg'}
                style={{
                  background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                  border: 'none',
                }}
              >
                Submit Quote Request
              </Button>
            )}
          </Group>
        </Stack>
      </Container>
    </Box>
  );
}

