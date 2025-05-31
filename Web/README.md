# 🦅 Web Raptor

<div align="center">
  <img src="public/shuriken-logo.svg" alt="Web Raptor Logo" width="100" height="100">
  
  **Web Reconnaissance Platform & Threat Intelligence**
  
  *Developed by Exploit*
  
  [![Next.js](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
  [![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-38B2AC?style=for-the-badge&logo=tailwind-css)](https://tailwindcss.com/)
  [![Vercel](https://img.shields.io/badge/Vercel-Deploy-black?style=for-the-badge&logo=vercel)](https://vercel.com/)
</div>

## 🚀 Features

- **🔍 Multi-Source Intelligence**: WHOIS, VirusTotal, IPInfo, URLVoid integration
- **🤖 AI-Enhanced Analysis**: OpenAI-powered threat intelligence reports
- **🛡️ Defensive Security**: Government-compliant reconnaissance tool
- **📱 Responsive Design**: Modern UI with glass morphism and cyber aesthetics
- **⚡ Real-time Analysis**: Live progress tracking and status updates
- **📊 Comprehensive Reports**: Detailed security assessments and recommendations
- **🌐 Network Mapping**: Infrastructure analysis and exposure assessment

## 🛠️ Tech Stack

- **Frontend**: Next.js 14, React 18, TypeScript
- **Styling**: Tailwind CSS, Custom animations, Glass morphism
- **APIs**: WHOIS XML, VirusTotal, IPInfo, URLVoid, OpenAI
- **Deployment**: Vercel, GitHub Actions
- **UI Components**: shadcn/ui, Lucide React icons

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v18.0.0 or higher)
- **npm** or **yarn** package manager
- **Git** for version control
- **Visual Studio Code** (recommended)

## 🔧 Development Setup

### Step 1: Clone the Repository

\`\`\`bash
# Clone the repository
git clone https://github.com/your-username/web-raptor-osint.git

# Navigate to project directory
cd web-raptor-osint
\`\`\`

### Step 2: Install Dependencies

\`\`\`bash
# Install all dependencies
npm install

# Or using yarn
yarn install
\`\`\`

### Step 3: Environment Configuration

Create a `.env.local` file in the root directory:

\`\`\`bash
# Copy the example environment file
cp .env.example .env.local
\`\`\`

Add your API keys to `.env.local`:

\`\`\`env
# Required API Keys
WHOISXML_API_KEY=your_whoisxml_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Optional: For enhanced features
IPINFO_TOKEN=your_ipinfo_token_here
URLVOID_API_KEY=your_urlvoid_api_key_here
\`\`\`

### Step 4: API Key Setup

#### WHOIS XML API
1. Visit [WhoisXML API](https://whoisxmlapi.com/)
2. Sign up for a free account
3. Get your API key from the dashboard
4. Add to `.env.local`

#### VirusTotal API
1. Visit [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Go to your profile and get the API key
4. Add to `.env.local`

#### OpenAI API (Optional)
1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Create an account and add billing
3. Generate an API key
4. Add to `.env.local`

#### IPInfo API (Optional)
1. Visit [IPInfo.io](https://ipinfo.io/)
2. Sign up for a free account
3. Get your access token
4. Add to `.env.local`

#### URLVoid API (Optional)
1. Visit [URLVoid](https://www.urlvoid.com/api/)
2. Sign up for an account
3. Get your API key
4. Add to `.env.local`

### Step 5: Run Development Server

\`\`\`bash
# Start the development server
npm run dev

# Or using yarn
yarn dev
\`\`\`

Open [http://localhost:3000](http://localhost:3000) in your browser.

## 🎨 Visual Studio Code Setup

### Recommended Extensions

Install these VS Code extensions for the best development experience:

\`\`\`json
{
  "recommendations": [
    "bradlc.vscode-tailwindcss",
    "esbenp.prettier-vscode",
    "ms-vscode.vscode-typescript-next",
    "formulahendry.auto-rename-tag",
    "christian-kohler.path-intellisense",
    "ms-vscode.vscode-json",
    "github.copilot"
  ]
}
\`\`\`

### VS Code Settings

Create `.vscode/settings.json`:

\`\`\`json
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "typescript.preferences.importModuleSpecifier": "relative",
  "tailwindCSS.experimental.classRegex": [
    ["cva\$$([^)]*)\$$", "[\"'`]([^\"'`]*).*?[\"'`]"],
    ["cx\$$([^)]*)\$$", "(?:'|\"|`)([^']*)(?:'|\"|`)"]
  ]
}
\`\`\`

### Debugging Configuration

Create `.vscode/launch.json`:

\`\`\`json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Next.js: debug server-side",
      "type": "node-terminal",
      "request": "launch",
      "command": "npm run dev"
    },
    {
      "name": "Next.js: debug client-side",
      "type": "chrome",
      "request": "launch",
      "url": "http://localhost:3000"
    }
  ]
}
\`\`\`

## 🚀 Deployment Guide

### GitHub Repository Setup

#### Step 1: Create GitHub Repository

\`\`\`bash
# Initialize git (if not already done)
git init

# Add all files
git add .

# Commit changes
git commit -m "Initial commit: Web Raptor OSINT Platform"

# Add remote origin
git remote add origin https://github.com/your-username/web-raptor-osint.git

# Push to GitHub
git push -u origin main
\`\`\`

#### Step 2: Repository Configuration

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Add the following secrets:

\`\`\`
WHOISXML_API_KEY
VIRUSTOTAL_API_KEY
OPENAI_API_KEY
IPINFO_TOKEN
URLVOID_API_KEY
\`\`\`

### Vercel Deployment

#### Method 1: Vercel CLI (Recommended)

\`\`\`bash
# Install Vercel CLI globally
npm install -g vercel

# Login to Vercel
vercel login

# Deploy to Vercel
vercel

# Follow the prompts:
# ? Set up and deploy "~/web-raptor-osint"? [Y/n] y
# ? Which scope do you want to deploy to? [Your Account]
# ? Link to existing project? [y/N] n
# ? What's your project's name? web-raptor-osint
# ? In which directory is your code located? ./
\`\`\`

#### Method 2: Vercel Dashboard

1. Visit [Vercel Dashboard](https://vercel.com/dashboard)
2. Click **"New Project"**
3. Import your GitHub repository
4. Configure project settings:
   - **Framework Preset**: Next.js
   - **Root Directory**: `./`
   - **Build Command**: `npm run build`
   - **Output Directory**: `.next`

#### Step 3: Environment Variables Setup

In Vercel Dashboard:

1. Go to your project settings
2. Navigate to **Environment Variables**
3. Add all your API keys:

\`\`\`
WHOISXML_API_KEY = your_api_key_here
VIRUSTOTAL_API_KEY = your_api_key_here
OPENAI_API_KEY = your_api_key_here
IPINFO_TOKEN = your_token_here
URLVOID_API_KEY = your_api_key_here
\`\`\`

4. Set environment for: **Production**, **Preview**, and **Development**

#### Step 4: Custom Domain (Optional)

1. In Vercel Dashboard, go to **Domains**
2. Add your custom domain
3. Configure DNS settings as instructed
4. Enable HTTPS (automatic)

### Automated Deployment

#### GitHub Actions Workflow

Create `.github/workflows/deploy.yml`:

\`\`\`yaml
name: Deploy to Vercel

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
          
      - name: Install dependencies
        run: npm ci
        
      - name: Run tests
        run: npm run test --if-present
        
      - name: Build application
        run: npm run build
        
      - name: Deploy to Vercel
        uses: amondnet/vercel-action@v25
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.ORG_ID }}
          vercel-project-id: ${{ secrets.PROJECT_ID }}
          vercel-args: '--prod'
\`\`\`

## 📱 Mobile Responsiveness

The application is fully responsive and optimized for:

- **Desktop**: 1920px and above
- **Laptop**: 1024px - 1919px
- **Tablet**: 768px - 1023px
- **Mobile**: 320px - 767px

### Key Responsive Features

- Adaptive grid layouts
- Collapsible navigation
- Touch-friendly interfaces
- Optimized typography scaling
- Progressive image loading

## 🔒 Security Considerations

- All API keys are server-side only
- Rate limiting implemented
- Input validation and sanitization
- CORS protection
- Environment variable security

## 🧪 Testing

\`\`\`bash
# Run unit tests
npm run test

# Run integration tests
npm run test:integration

# Run e2e tests
npm run test:e2e

# Generate coverage report
npm run test:coverage
\`\`\`

## 📊 Performance Optimization

- **Code Splitting**: Automatic route-based splitting
- **Image Optimization**: Next.js Image component
- **Caching**: API response caching
- **Compression**: Gzip compression enabled
- **CDN**: Vercel Edge Network

## 🛠️ Troubleshooting

### Common Issues

#### 1. API Key Errors
\`\`\`bash
# Check environment variables
echo $WHOISXML_API_KEY

# Restart development server
npm run dev
\`\`\`

#### 2. Build Errors
\`\`\`bash
# Clear Next.js cache
rm -rf .next

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
\`\`\`

#### 3. Deployment Issues
\`\`\`bash
# Check Vercel logs
vercel logs

# Redeploy
vercel --prod
\`\`\`

### Getting Help

- 📧 **Email**: info@exploit.com
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-username/web-raptor-osint/issues)
- 📖 **Documentation**: [Project Wiki](https://github.com/your-username/web-raptor-osint/wiki)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- **Exploit Team** - Development and security expertise
- **Open Source Community** - Various libraries and tools
- **API Providers** - WHOIS XML, VirusTotal, IPInfo, URLVoid
- **Vercel** - Hosting and deployment platform

---

<div align="center">
  <strong>Web Raptor v2.0 | Web Reconnaissance Platform</strong><br>
  Developed with ❤️ by <strong>Exploit</strong>
</div>
