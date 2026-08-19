import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Title,
  Text,
  Button,
  Group,
  Stack,
  Card,
  SimpleGrid,
  Badge,
  Box,
  Overlay,
  ThemeIcon,
  rem,
  Paper,
  Avatar,
  Rating,
  ActionIcon,
} from '@mantine/core';
import {
  IconShield,
  IconHeartHandshake,
  IconTrendingUp,
  IconCheck,
  IconArrowRight,
  IconPhone,
  IconMail,
  IconMapPin,
  IconQuote,
  IconLock,
  IconUserPlus,
} from '@tabler/icons-react';
import { useMediaQuery } from '@mantine/hooks';
import { Navbar } from '../components/Navigation/Navbar';
import { StickySignUp } from '../components/StickySignUp/StickySignUp';

export function HomePage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [animatedCount, setAnimatedCount] = useState(0);

  // Animated counter effect
  useEffect(() => {
    const target = 1000;
    const duration = 2000;
    const steps = 60;
    const increment = target / steps;
    let current = 0;

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        setAnimatedCount(target);
        clearInterval(timer);
      } else {
        setAnimatedCount(Math.floor(current));
      }
    }, duration / steps);

    return () => clearInterval(timer);
  }, []);

  const services = [
    {
      icon: IconShield,
      title: 'Life Insurance',
      description: 'Protect your family\'s future with comprehensive life insurance coverage that grows with you.',
      color: 'trustBlue',
      link: '/services/life-insurance',
    },
    {
      icon: IconHeartHandshake,
      title: 'Critical Illness',
      description: 'Financial protection when you need it most. Get a lump sum payment upon diagnosis.',
      color: 'calmingTeal',
      link: '/services/critical-illness',
    },
    {
      icon: IconTrendingUp,
      title: 'Disability Insurance',
      description: 'Protect your income and maintain your lifestyle if you\'re unable to work.',
      color: 'trustBlue',
      link: '/services/disability-insurance',
    },
  ];

  const features = [
    'Expert Canadian advisors',
    'Flexible payment options',
    'Fast claim processing',
    '24/7 customer support',
    'Digital document access',
    'Personalized coverage',
  ];

  const testimonials = [
    {
      name: 'Sarah Thompson',
      role: 'Mother of Two',
      content: 'Toniebee gave me peace of mind knowing my family is protected. The process was so easy and the advisor was incredibly helpful.',
      rating: 5,
      avatar: 'ST',
    },
    {
      name: 'Michael Chen',
      role: 'Small Business Owner',
      content: 'As a business owner, disability insurance was crucial. Toniebee found me the perfect policy that fits my needs and budget.',
      rating: 5,
      avatar: 'MC',
    },
    {
      name: 'Emily Rodriguez',
      role: 'Young Professional',
      content: 'I thought life insurance was complicated, but Toniebee made it simple. I feel secure about my future now.',
      rating: 5,
      avatar: 'ER',
    },
  ];

  return (
    <Box>
      <Navbar />
      <StickySignUp />

      {/* Hero Section - Cleaner gradient */}
      <Box
        style={{
          position: 'relative',
          minHeight: isMobile ? '85vh' : '90vh',
          display: 'flex',
          alignItems: 'center',
          background: 'linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%)',
          overflow: 'hidden',
        }}
      >
        {/* Subtle pattern overlay */}
        <Box
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            opacity: 0.05,
            backgroundImage: 'radial-gradient(circle at 2px 2px, white 1px, transparent 0)',
            backgroundSize: '40px 40px',
          }}
        />
        
        <Overlay
          gradient="linear-gradient(180deg, rgba(0, 0, 0, 0.1) 0%, rgba(0, 0, 0, 0.3) 100%)"
          opacity={0.2}
          zIndex={1}
        />
        
        <Container size="xl" style={{ position: 'relative', zIndex: 2 }} py={{ base: 'xl', sm: '3xl' }}>
          <Stack gap="xl" align="center" ta="center">
            <Badge
              size="lg"
              variant="light"
              color="white"
              style={{ 
                backdropFilter: 'blur(10px)', 
                backgroundColor: 'rgba(255, 255, 255, 0.2)',
                border: '1px solid rgba(255, 255, 255, 0.3)',
                color: 'white',
              }}
            >
              <Text c="white" fw={600} size="sm">
                Trusted by {animatedCount.toLocaleString()}+ Canadian Families
              </Text>
            </Badge>
            
            <Title
              order={1}
              size={isMobile ? rem(36) : rem(64)}
              fw={800}
              c="white"
              style={{
                textShadow: '0 4px 20px rgba(0, 0, 0, 0.3)',
                lineHeight: 1.1,
              }}
            >
              Protect What Matters Most
            </Title>
            
            <Text
              size={isMobile ? 'md' : 'xl'}
              c="white"
              maw={800}
              fw={400}
              style={{
                textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)',
                opacity: 1,
              }}
            >
              Your trusted partner in financial security. We help Canadian families secure their future with comprehensive insurance solutions tailored to your needs.
            </Text>
            
            <Group gap="md" mt="xl" justify="center" wrap="wrap">
              <Button
                size={isMobile ? 'md' : 'lg'}
                radius="xl"
                color="warmOrange"
                rightSection={<IconArrowRight size={20} />}
                onClick={() => navigate('/quote')}
                style={{
                  boxShadow: '0 8px 24px rgba(249, 115, 22, 0.4)',
                }}
              >
                Get Your Free Quote
              </Button>
              <Button
                size={isMobile ? 'md' : 'lg'}
                radius="xl"
                variant="white"
                color="dark"
                leftSection={<IconUserPlus size={20} />}
                onClick={() => navigate('/register')}
              >
                Sign Up Free
              </Button>
            </Group>

            {/* Sign up prompt */}
            <Paper
              p="md"
              radius="lg"
              mt="xl"
              style={{
                background: 'rgba(255, 255, 255, 0.1)',
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                maxWidth: 600,
              }}
            >
              <Group gap="sm" justify="center" wrap="wrap">
                <ThemeIcon size={32} radius="md" color="white" variant="light">
                  <IconLock size={18} />
                </ThemeIcon>
                <Text size="sm" c="white" fw={500} style={{ opacity: 1 }}>
                  Sign up to access your client portal, track policies, and manage your coverage
                </Text>
              </Group>
            </Paper>
          </Stack>
        </Container>
      </Box>

      {/* Services Section */}
      <Box
        style={{
          background: 'linear-gradient(180deg, #0F172A 0%, #1E293B 100%)',
        }}
        py={{ base: 'xl', sm: '5xl' }}
      >
        <Container size="xl">
          <Stack gap="xl" align="center">
          <Box ta="center" maw={700}>
            <Text
              size="sm"
              fw={600}
              c="trustBlue.3"
              tt="uppercase"
              mb="md"
            >
              Our Services
            </Text>
            <Title order={2} size={isMobile ? rem(28) : rem(40)} mb="md" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
              Comprehensive Insurance Solutions
            </Title>
            <Text size={isMobile ? 'sm' : 'md'} c="gray.1" fw={400} style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
              We offer a full range of insurance products designed to protect you and your loved ones at every stage of life.
            </Text>
          </Box>

          <SimpleGrid
            cols={{ base: 1, sm: 2, lg: 3 }}
            spacing={{ base: 'md', sm: 'xl' }}
            mt="xl"
          >
            {services.map((service) => (
              <Card
                key={service.title}
                shadow="lg"
                padding="xl"
                radius="lg"
                withBorder
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  backdropFilter: 'blur(10px)',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-8px)';
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                  e.currentTarget.style.boxShadow = '0 20px 40px rgba(0, 0, 0, 0.3)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
                  e.currentTarget.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
                }}
                onClick={() => navigate(service.link)}
              >
                <ThemeIcon
                  size={60}
                  radius="md"
                  variant="light"
                  color={service.color}
                  mb="md"
                >
                  <service.icon size={30} stroke={1.5} />
                </ThemeIcon>
                
                <Title order={3} size="h4" mb="sm" c="white" fw={700} style={{ textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }}>
                  {service.title}
                </Title>
                
                <Text size="sm" c="gray.1" mb="md" fw={400} style={{ textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)' }}>
                  {service.description}
                </Text>
                
                <Group gap={4} fw={600}>
                  <Text 
                    size="sm" 
                    fw={600}
                    style={{
                      background: `linear-gradient(135deg, var(--mantine-color-${service.color}-5) 0%, var(--mantine-color-${service.color}-7) 100%)`,
                      WebkitBackgroundClip: 'text',
                      WebkitTextFillColor: 'transparent',
                      backgroundClip: 'text',
                    }}
                  >
                    Learn More
                  </Text>
                  <IconArrowRight size={16} style={{ color: `var(--mantine-color-${service.color}-4)` }} />
                </Group>
              </Card>
            ))}
          </SimpleGrid>

          {/* Sign up CTA in services */}
          <Paper
            p="xl"
            radius="lg"
            mt="xl"
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '2px solid rgba(255, 255, 255, 0.1)',
              backdropFilter: 'blur(10px)',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.2)',
              width: '100%',
              maxWidth: 800,
            }}
          >
            <Group gap="lg" justify="space-between" wrap="wrap">
              <Stack gap="xs" style={{ flex: 1, minWidth: 250 }}>
                <Text fw={700} size="lg" c="white" style={{ textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }}>
                  Ready to Get Started?
                </Text>
                <Text size="sm" c="gray.1" fw={400} style={{ textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)' }}>
                  Sign up for free to access all services, get personalized quotes, and manage your policies online.
                </Text>
              </Stack>
              <Button
                size="lg"
                radius="xl"
                style={{
                  background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                  border: 'none',
                }}
                rightSection={<IconUserPlus size={18} />}
                onClick={() => navigate('/register')}
              >
                Sign Up Free
              </Button>
            </Group>
          </Paper>
        </Stack>
        </Container>
      </Box>

      {/* Why Choose Us Section - Cleaner background */}
      <Box
        style={{
          background: '#FAFBFC',
        }}
        py={{ base: 'xl', sm: '5xl' }}
      >
        <Container size="xl">
          <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xl">
            <Stack gap="lg">
              <Text
                size="sm"
                fw={600}
                c="trustBlue"
                tt="uppercase"
              >
                Why Choose Us
              </Text>
              <Title order={2} size={isMobile ? rem(28) : rem(40)} c="dark.9">
                Your Trusted Insurance Partner in Canada
              </Title>
              <Text size={isMobile ? 'sm' : 'md'} c="dark.8" fw={400}>
                We understand that insurance is more than just a policy—it's peace of mind for you and your family. Our expert advisors are here to guide you every step of the way.
              </Text>
              
              <SimpleGrid cols={2} spacing="md" mt="md">
                {features.map((feature) => (
                  <Group gap="xs" key={feature}>
                    <ThemeIcon size={24} radius="xl" color="successGreen" variant="light">
                      <IconCheck size={14} />
                    </ThemeIcon>
                    <Text size="sm" fw={500} c="dark.9">
                      {feature}
                    </Text>
                  </Group>
                ))}
              </SimpleGrid>
              
              <Button
                size={isMobile ? 'md' : 'lg'}
                radius="xl"
                color="trustBlue"
                mt="md"
                rightSection={<IconArrowRight size={20} />}
                onClick={() => navigate('/about')}
              >
                Learn More About Us
              </Button>
            </Stack>
            
            <Paper
              p="xl"
              radius="lg"
              shadow="lg"
              style={{
                background: 'white',
              }}
            >
              <Stack gap="md">
                <Group>
                  <ThemeIcon size={50} radius="md" color="trustBlue" variant="light">
                    <IconShield size={28} />
                  </ThemeIcon>
                  <div>
                    <Text fw={700} size="xl" c="dark.9">
                      Licensed & Certified
                    </Text>
                    <Text size="sm" c="dark.7" fw={400}>
                      Fully licensed insurance advisors
                    </Text>
                  </div>
                </Group>
                
                <Group>
                  <ThemeIcon size={50} radius="md" color="calmingTeal" variant="light">
                    <IconHeartHandshake size={28} />
                  </ThemeIcon>
                  <div>
                    <Text fw={700} size="xl" c="dark.9">
                      Personalized Service
                    </Text>
                    <Text size="sm" c="dark.7" fw={400}>
                      Tailored solutions for your unique needs
                    </Text>
                  </div>
                </Group>
                
                <Group>
                  <ThemeIcon size={50} radius="md" color="trustBlue" variant="light">
                    <IconTrendingUp size={28} />
                  </ThemeIcon>
                  <div>
                    <Text fw={700} size="xl" c="dark.9">
                      Competitive Rates
                    </Text>
                    <Text size="sm" c="dark.7" fw={400}>
                      Best prices from top Canadian insurers
                    </Text>
                  </div>
                </Group>
              </Stack>
            </Paper>
          </SimpleGrid>
        </Container>
      </Box>

      {/* Testimonials Section */}
      <Box
        style={{
          background: 'linear-gradient(180deg, #0F172A 0%, #1E293B 100%)',
        }}
        py={{ base: 'xl', sm: '5xl' }}
      >
        <Container size="xl">
          <Stack gap="xl" align="center">
          <Box ta="center" maw={700}>
            <Text
              size="sm"
              fw={600}
              c="trustBlue.3"
              tt="uppercase"
              mb="md"
            >
              Client Stories
            </Text>
            <Title order={2} size={isMobile ? rem(28) : rem(40)} mb="md" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
              Trusted by Canadian Families
            </Title>
            <Text size={isMobile ? 'sm' : 'md'} c="gray.1" fw={400} style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
              See what our clients have to say about their experience with Toniebee Insurance.
            </Text>
          </Box>

          <SimpleGrid
            cols={{ base: 1, md: 3 }}
            spacing={{ base: 'md', sm: 'xl' }}
            mt="xl"
          >
            {testimonials.map((testimonial) => (
              <Card
                key={testimonial.name}
                shadow="lg"
                padding="xl"
                radius="lg"
                withBorder
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  backdropFilter: 'blur(10px)',
                  position: 'relative',
                }}
              >
                <ThemeIcon
                  size={40}
                  radius="xl"
                  color="trustBlue"
                  variant="light"
                  style={{
                    position: 'absolute',
                    top: 16,
                    right: 16,
                  }}
                >
                  <IconQuote size={20} />
                </ThemeIcon>
                
                <Rating value={testimonial.rating} readOnly mb="md" />
                
                <Text size="sm" c="gray.0" mb="md" fw={400} style={{ fontStyle: 'italic', lineHeight: 1.6, textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }}>
                  "{testimonial.content}"
                </Text>
                
                <Group gap="sm" mt="auto">
                  <Avatar color="trustBlue" radius="xl">
                    {testimonial.avatar}
                  </Avatar>
                  <div>
                    <Text fw={600} size="sm" c="white" style={{ textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }}>
                      {testimonial.name}
                    </Text>
                    <Text size="xs" c="gray.2" fw={500} style={{ textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)' }}>
                      {testimonial.role}
                    </Text>
                  </div>
                </Group>
              </Card>
            ))}
          </SimpleGrid>
        </Stack>
        </Container>
      </Box>

      {/* CTA Section - Cleaner gradient */}
      <Box
        style={{
          background: 'linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%)',
        }}
        py={{ base: 'xl', sm: '5xl' }}
      >
        <Container size="xl">
          <Paper
            p={{ base: 'xl', sm: '3xl' }}
            radius="xl"
            style={{
              background: 'white',
              textAlign: 'center',
            }}
          >
            <Stack gap="lg" align="center" maw={700} mx="auto">
              <Title order={2} size={isMobile ? rem(28) : rem(40)} c="dark.9">
                Ready to Protect Your Future?
              </Title>
              <Text size={isMobile ? 'sm' : 'md'} c="dark.8" fw={400}>
                Sign up for free to get personalized quotes, access your client portal, and manage all your policies in one place.
              </Text>
              <Group gap="md" mt="md" justify="center" wrap="wrap">
                <Button
                  size={isMobile ? 'md' : 'lg'}
                  radius="xl"
                  color="warmOrange"
                  rightSection={<IconUserPlus size={20} />}
                  onClick={() => navigate('/register')}
                >
                  Sign Up Free
                </Button>
                <Button
                  size={isMobile ? 'md' : 'lg'}
                  radius="xl"
                  variant="outline"
                  color="trustBlue"
                  leftSection={<IconPhone size={20} />}
                  onClick={() => navigate('/contact')}
                >
                  Call Us Today
                </Button>
              </Group>
            </Stack>
          </Paper>
        </Container>
      </Box>

      {/* Contact Info Footer */}
      <Box
        style={{
          background: '#FFFFFF',
        }}
        py={{ base: 'xl', sm: '3xl' }}
      >
        <Container size="xl">
        <SimpleGrid
          cols={{ base: 1, sm: 3 }}
          spacing="xl"
        >
          <Group gap="md">
            <ThemeIcon size={40} radius="md" color="trustBlue" variant="light">
              <IconPhone size={20} />
            </ThemeIcon>
            <div>
              <Text fw={600} size="sm" mb={4} c="dark.9">
                Call Us
              </Text>
              <Text size="sm" c="dark.8" fw={400}>
                (555) 123-4567
              </Text>
            </div>
          </Group>
          
          <Group gap="md">
            <ThemeIcon size={40} radius="md" color="calmingTeal" variant="light">
              <IconMail size={20} />
            </ThemeIcon>
            <div>
              <Text fw={600} size="sm" mb={4} c="dark.9">
                Email Us
              </Text>
              <Text size="sm" c="dark.8" fw={400}>
                octmay71@gmail.com
              </Text>
            </div>
          </Group>
          
          <Group gap="md">
            <ThemeIcon size={40} radius="md" color="trustBlue" variant="light">
              <IconMapPin size={20} />
            </ThemeIcon>
            <div>
              <Text fw={600} size="sm" mb={4} c="dark.9">
                Location
              </Text>
              <Text size="sm" c="dark.8" fw={400}>
                Serving All of Canada
              </Text>
            </div>
          </Group>
        </SimpleGrid>
        </Container>
      </Box>
    </Box>
  );
}
