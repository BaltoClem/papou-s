<?php

namespace App\EntityListener;

use App\Entity\User;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Persistence\Event\LifecycleEventArgs;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserListener
{
    private UserPasswordHasherInterface $hasher;

    public function __construct(UserPasswordHasherInterface $hasher)
    {
        $this->hasher = $hasher;
    }


    public function prePersist(User $user)  // Permet d'encoder le password quand $user est persisté (se déclenche au premier persist) 
                                            // (en récupérant le plainPassword donné dans AppFixtures ou quand un utilisateur est créé)
    {
        $this->encodePassword($user);
    }


    public function preUpdate(User $user, LifecycleEventArgs $event)  // Permet d'encoder le password quand $user est modifié 
    // (en récupérant le plainPassword donné dans AppFixtures ou quand un utilisateur est modifié)
    // (se déclenche au flush(), mais nécessite une modification de colonne pour être déclenché ! Exemple : la colonne 'updatedAt") 
    {
        $user->setUpdatedAt(new \DateTimeImmutable());
        
        $this->encodePassword($user);
    }


    /**
     * Encode password based on plain password
     *
     * @param User $user
     * @return void
     */
    public function encodePassword(User $user) // Permet d'encoder le password si plainPassword n'est pas null (en récupérant le plainPassword donné dans AppFixtures)
    {
        if($user->getPlainPassword() === null)
        {
            return;
        }

        $user->setPassword($this->hasher->hashPassword($user, $user->getPlainPassword()));

        $user->setPlainPassword(null);
    }
}










?>