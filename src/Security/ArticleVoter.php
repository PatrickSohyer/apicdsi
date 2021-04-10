<?php

//  src/Security/ArticleVoter.php

namespace App\Security;

use App\Entity\User;
use App\Entity\Article;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class ArticleVoter extends Voter
{
    const EDIT = 'edit';
    const DELETE = 'delete';

    protected function supports(string $attribute, $subject)
    {
        if (!in_array($attribute, [self::EDIT, self::DELETE])) {
            return false;
        }
        if (!$subject instanceof Article) {
            return false;
        }

        return true;
    }
    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        if (!$user instanceof User) {
            return false;
        }

        $article = $subject;
        return $user->hasRoles('ROLE_ADMIN') || $user === $article->getAuthor();
    }
}
