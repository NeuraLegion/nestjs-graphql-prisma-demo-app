import { Field, InputType } from '@nestjs/graphql';

import { ArticleUncheckedCreateNestedManyWithoutTagsInput } from '../article/article-unchecked-create-nested-many-without-tags.input';

@InputType()
export class TagUncheckedCreateInput {
    @Field(() => String, { nullable: true })
    tagId?: string;

    @Field(() => String, { nullable: false })
    name!: string;

    @Field(() => ArticleUncheckedCreateNestedManyWithoutTagsInput, { nullable: true })
    articles?: ArticleUncheckedCreateNestedManyWithoutTagsInput;
}
