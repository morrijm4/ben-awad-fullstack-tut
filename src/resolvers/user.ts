import { User } from "../entities/User";
import { MyContext } from "src/types";
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Query,
  Resolver,
} from "type-graphql";
import argon2 from "argon2";

@InputType()
class UsernamePasswordInput {
  @Field(() => String)
  username: string;

  @Field(() => String)
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponce {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}

@Resolver()
export class UserResolver {
  @Query(() => User, { nullable: true })
  async me(@Ctx() { req, em }: MyContext) {
    // you are not logged in
    if (!req.session.userId) {
      return null;
    }

    const user = em.findOne(User, { id: req.session.userId });
    return user;
  }

  @Mutation(() => UserResponce)
  async register(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponce> {
    if (options.username.length <= 2) {
      return {
        errors: [
          {
            field: "username",
            message: "username is too small, must be longer than 2 characters",
          },
        ],
      };
    }

    if (options.password.length <= 3) {
      return {
        errors: [
          {
            field: "password",
            message: "password is too small, must be longer than 3 characters",
          },
        ],
      };
    }

    const hasedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      password: hasedPassword,
    });
    try {
      await em.persistAndFlush(user);
    } catch (err) {
      // duplicate username error
      if (err.code === "23505" /*|| err.detail.includes("already exists")*/) {
        return {
          errors: [
            {
              field: "username",
              message: "username already been taken",
            },
          ],
        };
      }
    }

    // store user id in session
    // this will set a cookie on the user
    // keep them logged in
    req.session.userId = user.id;

    return { user };
  }

  @Mutation(() => UserResponce)
  async login(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponce> {
    const user = await em.findOne(User, { username: options.username });
    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "username does not exsist",
          },
        ],
      };
    }
    const valid = await argon2.verify(user.password, options.password);
    if (!valid) {
      return {
        errors: [
          {
            field: "password",
            message: "password is incorrect",
          },
        ],
      };
    }

    req.session.userId = user.id;

    return { user };
  }
}
