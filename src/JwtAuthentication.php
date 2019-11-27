<?php declare(strict_types=1);

namespace Frengky\JwtAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token;

class JwtAuthentication
{
    /** @var \Lcobucci\JWT\Signer */
    protected $signer;

    /** @var array */
    protected $config;

    /** @var \Lcobucci\JWT\Token */
    protected $token;

    public function __construct(array $config) {
        $this->config = $config;

        if (substr($this->config['algorithm'], 0, 2) == 'HS') {
            if (empty($this->config['secret']) || strlen($this->config['secret']) < 32) {
                throw new \InvalidArgumentException('JWT_SECRET should be minimum 32 characters');
            }
        }
    }

    /**
     * Get the token from current request
     * 
     * @return \Lcobucci\JWT\Token|null
     */
    public function getToken(): ?Token {
        if (! empty($this->token)) {
            return $this->token;
        }
        
        $token = $this->getTokenFromRequest();
        if (! empty($token)) {
            $token = (new Parser())->parse((string) $token);
        }

        return $this->token = $token;
    }

    /**
     * Validate and verify the token from current request
     * 
     * @return bool
     */
    public function hasValidToken(): bool {
        $token = $this->getToken();

        if (empty($token)) {
            return false;
        }

        if ($token->getHeader('alg') != $this->config['algorithm']) {
            return false;
        }

        if (substr($this->config['algorithm'], 0, 2) == 'HS') {
            $key = new Key($this->config['secret']);
        } else {
            $key = new Key('file://' . realpath($this->config['public']));
        }

        if ($token->verify($this->provideSigner(), $key)) {
            return $token->validate($this->provideValidationData());
        }

        return false;
    }

    /**
     * @param Authenticable $authenticable
     * @param array $customClaims
     * 
     * @return string
     */
    public function createToken(Authenticatable $authenticable, array $customClaims = [], int $expiresAt = 0): string {
        $now = time();
        $expiresAt = $now + ($expiresAt > 0 ? $expiresAt : $this->config['expired']);

        $builder = (new Builder())
            ->issuedBy($this->config['issuer'])
            ->identifiedBy(Str::random(12), true)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($expiresAt)
            ->relatedTo($authenticable->getAuthIdentifier())
            ->permittedFor($this->config['issuer']);

        if (! empty($customClaims)) {
            foreach($customClaims as $key => $value) {
                $builder = $builder->set($key, $value);
            }
        }

        if (substr($this->config['algorithm'], 0, 2) == 'HS') {
            $key = new Key($this->config['secret']);
        } else {
            $key = new Key('file://'.realpath($this->config['private']), $this->config['passphrase']);
        }

        return (string) $builder->getToken($this->provideSigner(), $key);
    }

    /**
     * @return \Lcobucci\JWT\Signer
     */
    public function provideSigner(): Signer {
        if (! empty($this->signer)) {
            return $this->signer;
        }

        $algorithm = $this->config['algorithm'];

        $bits = substr($algorithm, 2);
        if (! in_array($bits, ['256', '384', '512'])) {
            throw new \InvalidArgumentException('unknown algorithm: ' . $algorithm);
        }

        $signerClass = '';
        switch(substr($algorithm, 0, 2)) {
            case 'HS':
                $signerClass = '\Lcobucci\JWT\Signer\Hmac\Sha' . $bits;
                break;
            case 'RS':
                $signerClass = '\Lcobucci\JWT\Signer\Rsa\Sha' . $bits;
                break;
            case 'ES':
                $signerClass = '\Lcobucci\JWT\Signer\Ecdsa\Sha' . $bits;
                break;
        }

        if (empty($signerClass)) {
            throw new \InvalidArgumentException('unknown algorithm: ' . $algorithm);
        }

        return $this->signer = new $signerClass;
    }

    /**
     * @return \Lcobucci\JWT\ValidationData
     */
    public function provideValidationData(): ValidationData {
        $validator = new ValidationData();
        $validator->setIssuer($this->config['issuer']);

        return $validator;
    }

    /**
     * Get the JWT token from the current request.
     *
     * @return string|null
     */
    public function getTokenFromRequest(): ?string {
        $request = request();

        $token = $request->query('token');
        if (empty($token)) {
            $token = $request->input('token');
        }
        if (empty($token)) {
            $token = $request->bearerToken();
        }

        return empty($token) ? null : $token;
    }    
}