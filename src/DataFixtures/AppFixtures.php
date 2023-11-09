<?php

namespace App\DataFixtures;

use Faker\Factory;
use App\Entity\User;
use Faker\Generator;
use App\Entity\Partner;
use App\Entity\Customer;
use Doctrine\Persistence\ObjectManager;
use Doctrine\Bundle\FixturesBundle\Fixture;

class AppFixtures extends Fixture
{
    /**
     * @var Generator
     */
    private Generator $faker;

    public function __construct()
    {
        $this->faker = Factory::create('fr_FR');
    }
    
    public function load(ObjectManager $manager): void
    {
        // !!!!!  ADMIN  !!!!

        $users = [];

        $admin = new User();  // On ajoute un administrateur
        $admin->setEmail('admin@papou.com')
            ->setRoles(['ROLE_USER', 'ROLE_ADMIN'])
            ->setPlainPassword('pass');

        $users[] = $admin;

        $manager->persist($admin);


        // !!!!!  CUSTOMERS  !!!!

        for ($l=1; $l <= 30; $l++)  // On ajoute 30 customers
        { 
            $customer = new Customer();
            $customer->setFirstname($this->faker->firstName);
            $customer->setLastname($this->faker->lastName);

            $firstname = $customer->getFirstname();
            $lastname = $customer->getLastname();
            // On convertit $firstname et $lastname en minuscules
            $firstname = mb_strtolower($firstname, 'UTF-8');
            $lastname = mb_strtolower($lastname, 'UTF-8');
            // On supprime les accents de $firstname et $lastname
            $firstname = iconv('UTF-8', 'ASCII//TRANSLIT', $firstname);
            $lastname = iconv('UTF-8', 'ASCII//TRANSLIT', $lastname);
            // On supprime tous les caractères non alphanumériques de $firstname et $lastname
            $firstname = preg_replace('/[^a-zA-Z0-9]/', '', $firstname);
            $lastname = preg_replace('/[^a-zA-Z0-9]/', '', $lastname);

            $customer->setEmail($firstname . "." . $lastname . "@mail.com");
            $customer->setPlainPassword('pass');
            $customer->setGenre('Non renseigné');
            $customer->setBirthdate($this->faker->dateTimeBetween('-90 years', '-8 years')); // Date de naissance entre -40 et -18 ans
            
            $users[] = $customer;

            $manager->persist($customer);
        }


        // !!!!!  PARTNERS  !!!!

        for ($l=1; $l <= 10; $l++)  // On ajoute 10 partners
        { 
            $partner = new Partner();
            $partner->setName($this->faker->company);

            $partnerName = $partner->getName();
            // On convertit $partnerName en minuscules
            $partnerName = mb_strtolower($partnerName, 'UTF-8');
            // On supprime les accents de $partnerName
            $partnerName = iconv('UTF-8', 'ASCII//TRANSLIT', $partnerName);
            // On supprime tous les caractères non alphanumériques de $partnerName
            $partnerName = preg_replace('/[^a-zA-Z0-9]/', '', $partnerName);

            $partner->setEmail($partnerName . "@mail.com");
            $partner->setPlainPassword('pass');
            $partner->setPhone($this->faker->phoneNumber);
            $partner->setType($this->faker->randomElement(['association', 'boutique']));
        
            $users[] = $partner;

            $manager->persist($partner);
        }







        $manager->flush();
    }
}
