import { Progress, Text, Box } from '@mantine/core';

interface PasswordStrengthMeterProps {
  password: string;
}

export function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
  if (!password) return null;

  function calculateStrength(password: string): { value: number; color: string; label: string; feedback: string[] } {
    let strength = 0;
    const feedback: string[] = [];
    
    const checks = {
      length12: password.length >= 12, // Minimum required
      length14: password.length >= 14, // Recommended
      length16: password.length >= 16, // Excellent
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
      noSequential: !/(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password),
      noRepeating: !/(.)\1{2,}/.test(password), // No 3+ repeating characters
      noCommon: !['password', '12345678', '123456789', '1234567890', 'qwerty', 'qwerty123', 'admin', 'letmein', 'welcome', 'monkey', 'password123', 'iloveyou', 'princess', 'rockyou', '123qwe', 'abc123', 'password1', 'admin123'].some(common => password.toLowerCase().includes(common)),
    };

    // Calculate strength (0-100) with weighted scoring
    if (checks.length12) strength += 15; // Base requirement
    if (checks.length14) strength += 10; // Bonus for longer
    if (checks.length16) strength += 5;  // Extra bonus
    if (checks.lowercase) strength += 12;
    if (checks.uppercase) strength += 12;
    if (checks.numbers) strength += 12;
    if (checks.special) strength += 12;
    if (checks.noSequential) strength += 11; // Bonus for avoiding patterns
    if (checks.noRepeating) strength += 11; // Bonus for avoiding repetition
    if (checks.noCommon) strength += 10; // Bonus for avoiding common passwords

    // Build feedback
    if (!checks.length12) feedback.push('• Use at least 12 characters');
    if (checks.length12 && !checks.length14) feedback.push('• Use 14+ characters for better security');
    if (!checks.lowercase) feedback.push('• Add lowercase letters');
    if (!checks.uppercase) feedback.push('• Add uppercase letters');
    if (!checks.numbers) feedback.push('• Add numbers');
    if (!checks.special) feedback.push('• Add special characters (!@#$%^&*)');
    if (!checks.noSequential) feedback.push('• Avoid sequential characters (abc, 123)');
    if (!checks.noRepeating) feedback.push('• Avoid repeating characters (aaa, 111)');
    if (!checks.noCommon) feedback.push('• Avoid common words (password, qwerty)');

    // Determine color and label
    let color = 'red';
    let label = 'Weak';
    
    if (strength >= 85) {
      color = 'green';
      label = 'Very Strong';
    } else if (strength >= 70) {
      color = 'green';
      label = 'Strong';
    } else if (strength >= 50) {
      color = 'yellow';
      label = 'Medium';
    } else if (strength >= 30) {
      color = 'orange';
      label = 'Fair';
    } else {
      color = 'red';
      label = 'Weak';
    }

    return { value: strength, color, label, feedback };
  }

  const { value, color, label, feedback } = calculateStrength(password);

  return (
    <Box mt="xs">
      <Progress value={value} color={color} size="sm" radius="xl" />
      <Text size="xs" c={color} mt={4} fw={500}>
        Password strength: {label}
      </Text>
      {value < 85 && feedback.length > 0 && (
        <Box mt={4}>
          {feedback.map((item, index) => (
            <Text key={index} size="xs" c="dimmed" mt={2}>
              {item}
            </Text>
          ))}
        </Box>
      )}
    </Box>
  );
}

